#!/usr/bin/python

# mininet tests for FAUCET
#
# * must be run as root
# * you can run a specific test case only, by adding the class name of the test
#   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest
#
# REQUIRES:
#
# * mininet 2.2.0 or later (Ubuntu 14 ships with 2.1.0, which is not supported)
#   use the "install from source" option from https://github.com/mininet/mininet/blob/master/INSTALL.
#   suggest ./util/install.sh -n
# * OVS 2.4.1 or later (Ubuntu 14 ships with 2.0.2, which is not supported)
# * VLAN utils (vconfig, et al - on Ubuntu, apt-get install vlan)
# * fuser
# * net-tools
# * iputils-ping
# * netcat-openbsd
# * tcpdump
# * exabgp

import ipaddr
import os
import sys
import re
import shutil
import tempfile
import time
import unittest
import yaml
import json
import requests
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import Host
from mininet.node import Intf
from mininet.topo import Topo
from mininet.util import dumpNodeConnections, pmonitor

FAUCET_DIR = os.getenv('FAUCET_DIR', '../src/ryu_faucet/org/onfsdn/faucet')

DPID = '1'
HARDWARE = 'Open vSwitch'
RYU_ADDR = "http://127.0.0.1:8080"

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
REQUIRED_TEST_PORTS = 4
PORT_MAP = {'port_1': 1, 'port_2': 2, 'port_3': 3, 'port_4': 4}
SWITCH_MAP = {}


class VLANHost(Host):

    def config(self, vlan=100, **params):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""
        super_config = super(VLANHost, self).config(**params)
        intf = self.defaultIntf()
        self.cmd('ifconfig %s inet 0' % intf)
        self.cmd('vconfig add %s %d' % (intf, vlan))
        self.cmd('ifconfig %s.%d inet %s' % (intf, vlan, params['ip']))
        vlan_intf_name = '%s.%d' % (intf, vlan)
        intf.name = vlan_intf_name
        self.nameToIntf[vlan_intf_name] = intf
        return super_config


class FAUCET(Controller):

    def __init__(self, name, cdir=FAUCET_DIR,
                 command='ryu-manager ryu.app.ofctl_rest faucet.py',
                 cargs='--ofp-tcp-listen-port=%s --verbose --use-stderr',
                 **kwargs):
        Controller.__init__(self, name, cdir=cdir,
                            command=command,
                            cargs=cargs, **kwargs)

class Gauge(Controller):

    def __init__(self, name, cdir=FAUCET_DIR,
                 command='ryu-manager gauge.py',
                 cargs='--ofp-tcp-listen-port=%s --verbose --use-stderr',
                 **kwargs):
        Controller.__init__(self, name, cdir=cdir,
                            command=command,
                            cargs=cargs, **kwargs)


class FaucetSwitchTopo(Topo):

    def build(self, n_tagged=0, tagged_vid=100, n_untagged=0):
        for host_n in range(n_tagged):
            host = self.addHost('ht_%s' % (host_n + 1),
                cls=VLANHost, vlan=tagged_vid)
        for host_n in range(n_untagged):
            host = self.addHost('hu_%s' % (host_n + 1))
        dpid = DPID
        if SWITCH_MAP:
            dpid = hex(int(DPID, 16) + 1)[2:]
            print 'mapped switch will use DPID %s' % dpid
        switch = self.addSwitch('s1', dpid=dpid)
        for host in self.hosts():
            self.addLink(host, switch)


class FaucetTest(unittest.TestCase):

    ONE_GOOD_PING = '1 packets transmitted, 1 received, 0% packet loss'
    CONFIG = ''
    CONTROLLER_IPV4 = '10.0.0.254'
    CONTROLLER_IPV6 = 'fc00::1:254'
    OFCTL = 'ovs-ofctl -OOpenFlow13'

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(self.tmpdir,
             'faucet.yaml')
        os.environ['GAUGE_CONFIG'] = os.path.join(self.tmpdir,
             'gauge.conf')
        open(os.environ['GAUGE_CONFIG'], 'w').write(
             os.environ['FAUCET_CONFIG'])
        os.environ['FAUCET_LOG'] = os.path.join(self.tmpdir,
             'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
             'faucet-exception.log')
        os.environ['GAUGE_LOG'] = os.path.join(self.tmpdir,
             'gauge.log')
        os.environ['GAUGE_EXCEPTION_LOG'] = os.path.join(self.tmpdir,
             'gauge-exception.log')
        self.debug_log_path = os.path.join(self.tmpdir, 'ofchannel.log')
        self.monitor_ports_file = os.path.join(self.tmpdir,
             'ports.txt')
        self.monitor_flow_table_file = os.path.join(self.tmpdir,
             'flow.txt')
        self.CONFIG = '\n'.join((
            self.get_config_header(
                DPID, HARDWARE, self.monitor_ports_file, self.monitor_flow_table_file),
            self.CONFIG % PORT_MAP,
            'ofchannel_log: "%s"' % self.debug_log_path))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.net = None
        self.topo = None

    def get_config_header(self, dpid, hardware,
                          monitor_ports_files, monitor_flow_table_file):
        return '''
---
dp_id: 0x%s
name: "faucet-1"
hardware: "%s"
monitor_ports: True
monitor_ports_interval: 2
monitor_ports_file: "%s"
monitor_flow_table: True
monitor_flow_table_interval: 2
monitor_flow_table_file: "%s"
''' % (dpid, hardware, monitor_ports_files, monitor_flow_table_file)

    def attach_physical_switch(self):
        switch = self.net.switches[0]
        hosts_count = len(self.net.hosts)
        for i, test_host_port in enumerate(sorted(SWITCH_MAP)):
            port_i = i + 1
            mapped_port_i = port_i + hosts_count
            phys_port = Intf(SWITCH_MAP[test_host_port], node=switch)
            switch.cmd('ifconfig %s up' % phys_port)
            switch.cmd('ovs-vsctl add-port %s %s' % (switch.name, phys_port.name))
            for port_pair in ((port_i, mapped_port_i), (mapped_port_i, port_i)):
                port_x, port_y = port_pair
                switch.cmd('%s add-flow %s in_port=%u,actions=output:%u' % (
                    self.OFCTL, switch.name, port_x, port_y))
        for _ in range(20):
            if (os.path.exists(self.debug_log_path) and
                os.path.getsize(self.debug_log_path) > 0):
                return
            time.sleep(1)
        print 'physical switch could not connect to controller'
        sys.exit(-1)

    def start_net(self):
        self.net = Mininet(self.topo, controller=FAUCET)
        # TODO: when running software only, also test gauge.
        if not SWITCH_MAP:
            faucet_port = self.net.controllers[0].port
            self.net.addController(
                name='gauge', controller=Gauge, port=faucet_port + 1)
        self.net.start()
        if SWITCH_MAP:
            self.attach_physical_switch()
        else:
            self.net.waitConnected()
            self.wait_until_matching_flow('OUTPUT:CONTROLLER')
        dumpNodeConnections(self.net.hosts)

    def tearDown(self):
        if self.net is not None:
            self.net.stop()
            # Mininet takes a long time to actually shutdown.
            # TODO: detect and block when Mininet isn't done.
            time.sleep(5)
        shutil.rmtree(self.tmpdir)

    def add_host_ipv6_address(self, host, ip_v6):
        host.cmd('ip -6 addr add %s dev %s' % (ip_v6, host.intf()))

    def one_ipv4_ping(self, host, dst):
        ping_result = host.cmd('ping -c1 %s' % dst)
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv4_controller_ping(self, host):
        self.one_ipv4_ping(host, self.CONTROLLER_IPV4)

    def one_ipv6_ping(self, host, dst, timeout=2):
        # TODO: retry our one ping. We should not have to retry.
        for _ in range(timeout):
            ping_result = host.cmd('ping6 -c1 %s' % dst)
            if re.search(self.ONE_GOOD_PING, ping_result):
                return
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv6_controller_ping(self, host):
        self.one_ipv6_ping(host, self.CONTROLLER_IPV6)

    def wait_until_matching_flow(self, exp_flow, timeout=10):
        for _ in range(timeout):
            dump_flows = json.loads(requests.get(
            RYU_ADDR+'/stats/flow/%s' % DPID).text)[DPID]
            for flow in dump_flows:
                # Re-transform the dictioray into str to re-use
                # the verify_ipv*_routing methods
                flow_str = json.dumps(flow)
                if re.search(exp_flow, flow_str):
                    return
            time.sleep(1)
        self.assertTrue(re.search(exp_flow, json.dumps(dump_flows)))

    def swap_host_macs(self, first_host, second_host):
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip):
        first_host.cmd(('ifconfig %s:0 %s netmask 255.255.255.0 up' %
            (first_host.intf(), first_host_routed_ip.ip)))
        second_host.cmd(('ifconfig %s:0 %s netmask 255.255.255.0 up' %
            (second_host.intf(), second_host_routed_ip.ip)))
        first_host.cmd(('route add -net %s gw %s' % (
                        second_host_routed_ip.masked(), self.CONTROLLER_IPV4)))
        second_host.cmd(('route add -net %s gw %s' % (
                         first_host_routed_ip.masked(), self.CONTROLLER_IPV4)))
        self.net.ping(hosts=(first_host, second_host))
        self.wait_until_matching_flow(
            """SET_FIELD: {eth_dst:%s.+"nw_dst": "%s""" % (
                first_host.MAC(), first_host_routed_ip.masked().with_netmask))
        self.wait_until_matching_flow(
            """SET_FIELD: {eth_dst:%s.+"nw_dst": "%s""" % (
                second_host.MAC(), second_host_routed_ip.masked().with_netmask))
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip):
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip)
        self.add_host_ipv6_address(second_host, second_host_routed_ip)
        first_host.cmd('ip -6 route add %s via %s' % (
            second_host_routed_ip.masked(), self.CONTROLLER_IPV6))
        second_host.cmd('ip -6 route add %s via %s' % (
            first_host_routed_ip.masked(), self.CONTROLLER_IPV6))
        exp_ipv6 = "%s/%s" % (first_host_routed_ip.masked().ip, first_host_routed_ip.netmask)
        self.wait_until_matching_flow(
            """SET_FIELD: {eth_dst:%s.+"ipv6_dst": "%s""" % (
                first_host.MAC(), exp_ipv6))
        exp_ipv6 = "%s/%s" % (first_host_routed_ip.masked().ip, first_host_routed_ip.netmask)
        self.wait_until_matching_flow(
            """SET_FIELD: {eth_dst:%s.+"ipv6_dst": "%s""" % (
                second_host.MAC(), exp_ipv6))
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv6_ping(second_host, first_host_routed_ip.ip)


class FaucetUntaggedTest(FaucetTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
"""

    def setUp(self):
        super(FaucetUntaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_untagged=4)
        self.start_net()

    def test_untagged(self):
        self.assertEquals(0, self.net.pingAll())
        # TODO: a smoke test only - are flow/port stats accumulating
        if not SWITCH_MAP:
           assert os.stat(self.monitor_ports_file).st_size > 0
           assert os.stat(self.monitor_flow_table_file).st_size > 0


class FaucetTaggedAndUntaggedVlanTest(FaucetTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "mixed"
        unicast_flood: False
"""

    def setUp(self):
        super(FaucetTaggedAndUntaggedVlanTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_tagged=1, n_untagged=3)
        self.start_net()

    def test_untagged(self):
        self.net.pingAll()


class FaucetUntaggedMaxHostsTest(FaucetUntaggedTest):

    CONFIG = """
timeout: 60
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        max_hosts: 2
"""

    def test_untagged(self):
        for _ in range(3):
            self.net.pingAll()
            learned_hosts = set()
            for host in self.net.hosts:
                arp_output = host.cmd('arp -an')
                for arp_line in arp_output.splitlines():
                    arp_match = re.search(r'at ([\:a-f\d]+)', arp_line)
                    if arp_match:
                        learned_hosts.add(arp_match.group(1))
            if len(learned_hosts) == 2:
                break
            time.sleep(1)
        self.assertEquals(2, len(learned_hosts))


class FaucetUntaggedHUPTest(FaucetUntaggedTest):

    def test_untagged(self):
        controller = self.net.controllers[0]
        switch = self.net.switches[0]
        for _ in range(3):
            # ryu is a subprocess, so need PID of that.
            controller.cmd('fuser %s/tcp -k -1')
            self.assertTrue(switch.connected())
            self.assertEquals(0, self.net.pingAll())


class FaucetUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):

    CONFIG = """
arp_neighbor_timeout: 2
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        controller_ips: ["10.0.0.254/24"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_address: "127.0.0.1"
        bgp_neighbor_as: 2
"""

    def test_untagged(self):
        exabgp_conf = """
group test {
  router-id 2.2.2.2;
  neighbor 127.0.0.1 {
    passive;
    local-address 127.0.0.1;
    peer-as 1;
    local-as 2;
    static {
      route 10.0.1.0/24 next-hop 10.0.0.1 local-preference 100;
      route 10.0.2.0/24 next-hop 10.0.0.2 local-preference 100;
      route 10.0.3.0/24 next-hop 10.0.0.2 local-preference 100;
   }
 }
}
"""
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="127.0.0.1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> /dev/null > %s &' % (exabgp_conf_file, exabgp_log))
        # wait until BGP is successful and routes installed
        self.wait_until_matching_flow('10.0.3.0', timeout=30)
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        second_host_routed_ip2 = ipaddr.IPv4Network('10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)

class FaucetUntaggedIPv4RouteTest(FaucetUntaggedTest):

    CONFIG = """
arp_neighbor_timeout: 2
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        controller_ips: ["10.0.0.254/24"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_address: "127.0.0.1"
        bgp_neighbor_as: 2
        routes:
            - route:
                ip_dst: "10.0.1.0/24"
                ip_gw: "10.0.0.1"
            - route:
                ip_dst: "10.0.2.0/24"
                ip_gw: "10.0.0.2"
            - route:
                ip_dst: "10.0.3.0/24"
                ip_gw: "10.0.0.2"
"""

    def test_untagged(self):
        exabgp_conf = """
group test {
  process test {
    encoder json;
    neighbor-changes;
    receive-routes;
    run /bin/cat;
  }
  router-id 2.2.2.2;
  neighbor 127.0.0.1 {
    passive;
    local-address 127.0.0.1;
    peer-as 1;
    local-as 2;
  }
}
"""
	exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="127.0.0.1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> /dev/null > %s &' % (exabgp_conf_file, exabgp_log))
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        second_host_routed_ip2 = ipaddr.IPv4Network('10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)
        # exabgp should have received our BGP updates
        for i in range(30):
            updates = controller.cmd(
                'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                break
            time.sleep(1)
        assert re.search('10.0.0.0/24 next-hop 10.0.0.254', updates)
        assert re.search('10.0.1.0/24 next-hop 10.0.0.1', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)


class FaucetUntaggedNoVLanUnicastFloodTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
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

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        for _ in range(3):
            self.swap_host_macs(first_host, second_host)
            # TODO: sometimes slow to relearn
            self.assertTrue(self.net.ping((first_host, second_host)) <= 50)


class FaucetUntaggedHostPermanentLearnTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
        permanent_learn: True
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
"""

    def test_untagged(self):
        self.assertEqual(0, self.net.pingAll())
        first_host, second_host, third_host = self.net.hosts[0:3]
        # 3rd host impersonates 1st, 3rd host breaks but 1st host still OK
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        # 3rd host stops impersonating, now everything fine again.
        third_host.setMAC(original_third_host_mac)
        self.assertEqual(0, self.net.pingAll())


class FaucetUntaggedControlPlaneTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        controller_ips: ["10.0.0.254/24", "fc00::1:254/112"]
"""

    def test_ping_controller(self):
        first_host, second_host = self.net.hosts[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        # Verify IPv4 and IPv6 connectivity between first two hosts.
        self.one_ipv4_ping(first_host, second_host.IP())
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        # Verify first two hosts can ping controller over both IPv4 and IPv6
        for host in first_host, second_host:
            self.one_ipv4_controller_ping(host)
            self.one_ipv6_controller_ping(host)


class FaucetTaggedAndUntaggedTest(FaucetTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        tagged_vlans: [100]
        description: "b2"
    %(port_3)d:
        native_vlan: 101
        description: "b3"
    %(port_4)d:
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
        self.start_net()

    def test_seperate_untagged_tagged(self):
        tagged_host_pair = self.net.hosts[0:1]
        untagged_host_pair = self.net.hosts[2:3]
        # hosts within VLANs can ping each other
        self.assertEquals(0, self.net.ping(tagged_host_pair))
        self.assertEquals(0, self.net.ping(untagged_host_pair))
        # hosts cannot ping hosts in other VLANs
        self.assertEquals(100,
            self.net.ping([tagged_host_pair[0], untagged_host_pair[0]]))


class FaucetUntaggedACLTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
        acl_in: 1
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
acls:
    %(port_1)d:
        - rule:
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 5001
            actions:
                allow: 0
        - rule:
            actions:
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


class FaucetUntaggedACLMirrorTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
        acl_in: 1
    %(port_2)d:
        native_vlan: 100
        description: "b2"
        acl_in: 1
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
acls:
    %(port_1)d:
        - rule:
            actions:
                allow: 1
                mirror: %(port_3)d
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


class FaucetUntaggedOutputTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
        acl_in: 1
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        unicast_flood: False
acls:
    %(port_1)d:
        - rule:
            dl_dst: "01:02:03:04:05:06"
            actions:
                output:
                    dl_dst: "06:06:06:06:06:06"
                    port: %(port_2)d
"""

    def test_untagged(self):
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        # we expected to see the rewritten address.
        tcpdump_filter = 'ether dst %s and icmp' % '06:06:06:06:06:06'
        tcpdump_out = second_host.popen(
            'timeout 10s tcpdump -e -n -v -c 2 -U %s' % tcpdump_filter)
        # wait for tcpdump to start
        time.sleep(1)
        popens = {second_host: tcpdump_out}
        first_host.cmd('arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06'))
        first_host.cmd('ping -c1  %s' % second_host.IP())
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == second_host:
                tcpdump_txt += line.strip()
        self.assertFalse(tcpdump_txt == '')
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))


class FaucetUntaggedMirrorTest(FaucetUntaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
        mirror: %(port_1)d
    %(port_4)d:
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

    CONFIG = """
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        tagged_vlans: [100]
        description: "b2"
    %(port_3)d:
        tagged_vlans: [100]
        description: "b3"
    %(port_4)d:
        tagged_vlans: [100]
        description: "b4"
vlans:
    100:
        description: "tagged"
"""

    def setUp(self):
        super(FaucetTaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(n_tagged=4)
        self.start_net()

    def test_tagged(self):
        self.assertEquals(0, self.net.pingAll())


class FaucetTaggedControlPlaneTest(FaucetTaggedTest):

    CONFIG = """
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        tagged_vlans: [100]
        description: "b2"
    %(port_3)d:
        tagged_vlans: [100]
        description: "b3"
    %(port_4)d:
        tagged_vlans: [100]
        description: "b4"
vlans:
    100:
        description: "tagged"
        controller_ips: ["10.0.0.254/24", "fc00::1:254/112"]
"""

    def test_ping_controller(self):
        first_host, second_host = self.net.hosts[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        # Verify IPv4 and IPv6 connectivity between first two hosts.
        self.one_ipv4_ping(first_host, second_host.IP())
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        # Verify first two hosts can ping controller over both IPv4 and IPv6
        for host in first_host, second_host:
            self.one_ipv4_controller_ping(host)
            self.one_ipv6_controller_ping(host)


class FaucetTaggedIPv4RouteTest(FaucetTaggedTest):

    CONFIG = """
arp_neighbor_timeout: 2
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        tagged_vlans: [100]
        description: "b2"
    %(port_3)d:
        tagged_vlans: [100]
        description: "b3"
    %(port_4)d:
        tagged_vlans: [100]
        description: "b4"
vlans:
    100:
        description: "tagged"
        controller_ips: ["10.0.0.254/24"]
        routes:
            - route:
                ip_dst: "10.0.1.0/24"
                ip_gw: "10.0.0.1"

            - route:
                ip_dst: "10.0.2.0/24"
                ip_gw: "10.0.0.2"
"""

    def test_tagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)


class FaucetUntaggedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG = """
arp_neighbor_timeout: 2
interfaces:
    %(port_1)d:
        native_vlan: 100
        description: "b1"
    %(port_2)d:
        native_vlan: 100
        description: "b2"
    %(port_3)d:
        native_vlan: 100
        description: "b3"
    %(port_4)d:
        native_vlan: 100
        description: "b4"
vlans:
    100:
        description: "untagged"
        controller_ips: ["fc00::1:254/112"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_address: "::1"
        bgp_neighbor_as: 2
        routes:
            - route:
                ip_dst: "fc00::10:0/112"
                ip_gw: "fc00::1:1"
            - route:
                ip_dst: "fc00::20:0/112"
                ip_gw: "fc00::1:2"
            - route:
                ip_dst: "fc00::30:0/112"
                ip_gw: "fc00::1:2"
"""

    def test_untagged(self):
        exabgp_conf = """
group test {
  process test {
    encoder json;
    neighbor-changes;
    receive-routes;
    run /bin/cat;
  }
  router-id 2.2.2.2;
  neighbor ::1 {
    passive;
    local-address ::1;
    peer-as 1;
    local-as 2;
  }
}
"""
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="::1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> /dev/null > %s &' % (exabgp_conf_file, exabgp_log))
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        second_host_routed_ip2 = ipaddr.IPv6Network('fc00::30:1/112')
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        # exabgp should have received our BGP updates
        for i in range(30):
            updates = controller.cmd(
                'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                break
            time.sleep(1)
        assert re.search('fc00::1:0/112 next-hop fc00::1:254', updates)
        assert re.search('fc00::10:0/112 next-hop fc00::1:1', updates)
        assert re.search('fc00::20:0/112 next-hop fc00::1:2', updates)
        assert re.search('fc00::30:0/112 next-hop fc00::1:2', updates)


class FaucetTaggedIPv6RouteTest(FaucetTaggedTest):

    CONFIG = """
arp_neighbor_timeout: 2
interfaces:
    %(port_1)d:
        tagged_vlans: [100]
        description: "b1"
    %(port_2)d:
        tagged_vlans: [100]
        description: "b2"
    %(port_3)d:
        tagged_vlans: [100]
        description: "b3"
    %(port_4)d:
        tagged_vlans: [100]
        description: "b4"
vlans:
    100:
        description: "tagged"
        controller_ips: ["fc00::1:254/112"]
        routes:
            - route:
                ip_dst: "fc00::10:0/112"
                ip_gw: "fc00::1:1"
            - route:
                ip_dst: "fc00::20:0/112"
                ip_gw: "fc00::1:2"
"""

    def test_tagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)


def import_config():
    try:
        with open(HW_SWITCH_CONFIG_FILE, 'r') as config_file:
            config = yaml.load(config_file)
    except:
        print 'Could not load YAML config data from %s' % HW_SWITCH_CONFIG_FILE
        sys.exit(-1)
    if 'hw_switch' in config and config['hw_switch']:
        required_config = ['dp_ports']
        for required_key in required_config:
            if required_key not in config:
                print '%s must be specified in %s to use HW switch.' % (
                    required_key, HW_SWITCH_CONFIG_FILE)
                sys.exit(-1)
        dp_ports = config['dp_ports']
        if len(dp_ports) != REQUIRED_TEST_PORTS:
            print ('Exactly %u dataplane ports are required, '
                   '%d are provided in %s.' %
                   (REQUIRED_TEST_PORTS, len(dp_ports), HW_SWITCH_CONFIG_FILE))
        for i, switch_port in enumerate(dp_ports):
            test_port_name = 'port_%u' % (i+1)
            global PORT_MAP
            PORT_MAP[test_port_name] = switch_port
            global SWITCH_MAP
            SWITCH_MAP[test_port_name] = dp_ports[switch_port]
        if 'dpid' in config:
            global DPID
            DPID = config['dpid']
        if 'hardware' in config:
            global HARDWARE
            HARDWARE = config['hardware']


if __name__ == '__main__':
    import_config()
    unittest.main()
