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
#   use the "install from source" option from
#   https://github.com/mininet/mininet/blob/master/INSTALL.
#   suggest ./util/install.sh -n
# * OVS 2.3.1 or later (Ubuntu 14 ships with 2.0.2, which is not supported)
# * VLAN utils (vconfig, et al - on Ubuntu, apt-get install vlan)
# * fuser
# * net-tools
# * iputils-ping
# * netcat-openbsd
# * tcpdump
# * exabgp
# * pylint


import inspect
import os
import sys
import random
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

import json
import ipaddr
import requests
import yaml

from concurrencytest import ConcurrentTestSuite, fork_for_tests
from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import Host
from mininet.node import Intf
from mininet.node import OVSSwitch
from mininet.topo import Topo
from mininet.util import dumpNodeConnections, pmonitor

# list of required external dependencies
# external binary, argument to get version,
# RE to check present RE to get version, minimum required version.
EXTERNAL_DEPENDENCIES = (
    ('ryu-manager', ['--version'],
     'ryu-manager', r'ryu-manager (\d+\.\d+)\n', float(4.4)),
    ('ovs-vsctl', ['--version'], 'Open vSwitch',
     r'ovs-vsctl\s+\(Open vSwitch\)\s+(\d+\.\d+)\.\d+\n', float(2.3)),
    ('tcpdump', ['-h'], 'tcpdump',
     r'tcpdump\s+version\s+(\d+\.\d+)\.\d+\n', float(4.5)),
    ('nc', [], 'nc from the netcat-openbsd', '', 0),
    ('vconfig', [], 'the VLAN you are talking about', '', 0),
    ('fuser', ['-V'], r'fuser \(PSmisc\)',
     r'fuser \(PSmisc\) (\d+\.\d+)\n', float(22.0)),
    ('mn', ['--version'], r'\d+\.\d+.\d+',
     r'(\d+\.\d+).\d+', float(2.2)),
    ('exabgp', ['--version'], 'ExaBGP',
     r'ExaBGP : (\d+\.\d+).\d+', float(3.4)),
    ('pip', ['show', 'influxdb'], 'influxdb',
     r'Version:\s+(\d+\.\d+)\.\d+', float(3.0)),
    ('pylint', ['--version'], 'pylint',
     r'pylint (\d+\.\d+).\d+,', float(1.6)),
)

FAUCET_DIR = os.getenv('FAUCET_DIR', '../src/ryu_faucet/org/onfsdn/faucet')

# Must pass with 0 lint errors
# TODO: eliminate existing lint errors so all files can be checked.
FAUCET_LINT_SRCS = (
    'faucet.py',
    'gauge.py',
    'valve.py',
)

# Maximum number of parallel tests to run at once
MAX_PARALLEL_TESTS = 20

DPID = '1'
HARDWARE = 'Open vSwitch'

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
REQUIRED_TEST_PORTS = 4
PORT_MAP = {'port_1': 1, 'port_2': 2, 'port_3': 3, 'port_4': 4}
SWITCH_MAP = {}


def str_int_dpid(hex_dpid):
    return str(int(hex_dpid, 16))


# TODO: applications should retry if port not really free
def find_free_port():
    free_socket = socket.socket()
    free_socket.bind(('', 0))
    free_port = free_socket.getsockname()[1]
    free_socket.close()
    return free_port


class FaucetSwitch(OVSSwitch):

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name=name, datapath='kernel', **params)


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
        name = 'faucet-%u' % os.getpid()
        port = find_free_port()
        self.ofctl_port = find_free_port()
        cargs = '--wsapi-port=%u %s' % (self.ofctl_port, cargs)
        Controller.__init__(
            self, name, cdir=cdir, command=command, port=port, cargs=cargs, **kwargs)


class Gauge(Controller):

    def __init__(self, name, cdir=FAUCET_DIR,
                 command='ryu-manager gauge.py',
                 cargs='--ofp-tcp-listen-port=%s --verbose --use-stderr',
                 **kwargs):
        name = 'gauge-%u' % os.getpid()
        port = find_free_port()
        Controller.__init__(
            self, name, cdir=cdir, command=command, port=port, cargs=cargs, **kwargs)


class FaucetSwitchTopo(Topo):

    def build(self, dpid=0, n_tagged=0, tagged_vid=100, n_untagged=0):
        pid = os.getpid()
        for host_n in range(n_tagged):
            host = self.addHost('t%x%s' % (pid % 0xff, host_n + 1),
                                cls=VLANHost, vlan=tagged_vid)
        for host_n in range(n_untagged):
            host = self.addHost('u%x%s' % (pid % 0xff, host_n + 1))
        if SWITCH_MAP:
            dpid = int(dpid, 16) + 1
            print 'mapped switch will use DPID %s' % dpid
        switch = self.addSwitch(
            's1%x' % pid, cls=FaucetSwitch, listenPort=find_free_port(), dpid=dpid)
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
        os.environ['FAUCET_CONFIG'] = os.path.join(
            self.tmpdir, 'faucet.yaml')
        os.environ['GAUGE_CONFIG'] = os.path.join(
            self.tmpdir, 'gauge.conf')
        open(os.environ['GAUGE_CONFIG'], 'w').write(
            os.environ['FAUCET_CONFIG'])
        os.environ['FAUCET_LOG'] = os.path.join(
            self.tmpdir, 'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(
            self.tmpdir, 'faucet-exception.log')
        os.environ['GAUGE_LOG'] = os.path.join(
            self.tmpdir, 'gauge.log')
        os.environ['GAUGE_EXCEPTION_LOG'] = os.path.join(
            self.tmpdir, 'gauge-exception.log')
        self.debug_log_path = os.path.join(
            self.tmpdir, 'ofchannel.log')
        self.monitor_ports_file = os.path.join(
            self.tmpdir, 'ports.txt')
        self.monitor_flow_table_file = os.path.join(
            self.tmpdir, 'flow.txt')
        if SWITCH_MAP:
            self.dpid = DPID
        else:
            self.dpid = str(random.randint(1, 2**32))
        self.CONFIG = '\n'.join((
            self.get_config_header(
                self.dpid, HARDWARE, self.monitor_ports_file, self.monitor_flow_table_file),
            self.CONFIG % PORT_MAP,
            'ofchannel_log: "%s"' % self.debug_log_path))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.net = None
        self.topo = None

    def get_config_header(self, dpid, hardware,
                          monitor_ports_files, monitor_flow_table_file):
        return '''
---
dp_id: %s
name: "faucet-1"
hardware: "%s"
monitor_ports: True
monitor_ports_interval: 5
monitor_ports_file: "%s"
monitor_flow_table: True
monitor_flow_table_interval: 5
monitor_flow_table_file: "%s"
''' % (str_int_dpid(dpid), hardware, monitor_ports_files, monitor_flow_table_file)

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
            self.net.addController(controller=Gauge)
        self.net.start()
        if SWITCH_MAP:
            self.attach_physical_switch()
        else:
            for controller in self.net.controllers:
                controller.isAvailable()
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
        ofctl_url = 'http://127.0.0.1:%u' % self.net.controllers[0].ofctl_port
        for _ in range(timeout):
            int_dpid = str_int_dpid(self.dpid)
            ofctl_result = json.loads(requests.get(
                '%s/stats/flow/%s' % (ofctl_url, int_dpid)).text)
            dump_flows = ofctl_result[int_dpid]
            for flow in dump_flows:
                # Re-transform the dictionary into str to re-use
                # the verify_ipv*_routing methods
                flow_str = json.dumps(flow)
                if re.search(exp_flow, flow_str):
                    return
            time.sleep(1)
        self.assertTrue(re.search(exp_flow, json.dumps(dump_flows)))

    def wait_until_matching_route_as_flow(self, nexthop, prefix):
        if prefix.version == 6:
            exp_prefix = '/'.join(
                (str(prefix.masked().ip), str(prefix.netmask)))
            nw_dst_match = '"ipv6_dst": "%s"' % exp_prefix
        else:
            exp_prefix = prefix.masked().with_netmask
            nw_dst_match = '"nw_dst": "%s"' % exp_prefix
        self.wait_until_matching_flow(
            'SET_FIELD: {eth_dst:%s}.+%s'% (nexthop, nw_dst_match))

    def swap_host_macs(self, first_host, second_host):
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip):
        first_host.cmd(('ifconfig %s:0 %s netmask 255.255.255.0 up' % (
            first_host.intf(), first_host_routed_ip.ip)))
        second_host.cmd(('ifconfig %s:0 %s netmask 255.255.255.0 up' % (
            second_host.intf(), second_host_routed_ip.ip)))
        first_host.cmd(('route add -net %s gw %s' % (
            second_host_routed_ip.masked(), self.CONTROLLER_IPV4)))
        second_host.cmd(('route add -net %s gw %s' % (
            first_host_routed_ip.masked(), self.CONTROLLER_IPV4)))
        self.net.ping(hosts=(first_host, second_host))
        self.wait_until_matching_route_as_flow(
            first_host.MAC(), first_host_routed_ip)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), second_host_routed_ip)
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv4_routing_mesh(self):
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

    def setup_ipv6_hosts_addresses(self, first_host, first_host_ip,
                                   first_host_routed_ip, second_host,
                                   second_host_ip, second_host_routed_ip):
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip)
        self.add_host_ipv6_address(second_host, second_host_routed_ip)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip):
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        first_host.cmd('ip -6 route add %s via %s' % (
            second_host_routed_ip.masked(), self.CONTROLLER_IPV6))
        second_host.cmd('ip -6 route add %s via %s' % (
            first_host_routed_ip.masked(), self.CONTROLLER_IPV6))
        self.wait_until_matching_route_as_flow(
            first_host.MAC(), first_host_routed_ip)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), second_host_routed_ip)
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv6_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv6_routing_mesh(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        second_host_routed_ip2 = ipaddr.IPv6Network('fc00::30:1/112')
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.wait_until_matching_flow('fc00::30:', timeout=30)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)


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
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_untagged=4)
        self.start_net()

    def test_untagged(self):
        self.assertEquals(0, self.net.pingAll())
        # TODO: a smoke test only - are flow/port stats accumulating
        if not SWITCH_MAP:
            for _ in range(5):
                if (os.path.exists(self.monitor_ports_file) and
                        os.path.exists(self.monitor_flow_table_file)):
                    break
                time.sleep(1)
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
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_tagged=1, n_untagged=3)
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
        unicast_flood: False
"""

    def test_untagged(self):
        for host_x in self.net.hosts:
            for host_y in self.net.hosts:
                    host_x.cmd('arp -d %s' % host_y.IP())
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


class FaucetSingleUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):

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
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
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
        # wait until 10.0.0.1 has been resolved
        self.wait_until_matching_flow('10.99.99.0', timeout=30)
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="127.0.0.1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> %s > %s &' % (exabgp_conf_file, exabgp_err, exabgp_log))
        # wait until BGP is successful and routes installed
        self.wait_until_matching_flow('10.0.3.0', timeout=30)
        self.verify_ipv4_routing_mesh()


class FaucetSingleUntaggedIPv4RouteTest(FaucetUntaggedTest):

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
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="127.0.0.1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> %s > %s &' % (exabgp_conf_file, exabgp_err, exabgp_log))
        self.verify_ipv4_routing_mesh()
        # exabgp should have received our BGP updates
        for _ in range(30):
            updates = controller.cmd(
                r'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
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
        self.net.pingAll()
        # Can be slow to learn, but everyone must have connectivity.
        self.assertEqual(0, self.net.pingAll())


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
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_tagged=2, n_untagged=2)
        self.start_net()

    def test_seperate_untagged_tagged(self):
        tagged_host_pair = self.net.hosts[0:1]
        untagged_host_pair = self.net.hosts[2:3]
        # hosts within VLANs can ping each other
        self.assertEquals(0, self.net.ping(tagged_host_pair))
        self.assertEquals(0, self.net.ping(untagged_host_pair))
        # hosts cannot ping hosts in other VLANs
        self.assertEquals(
            100, self.net.ping([tagged_host_pair[0], untagged_host_pair[0]]))


class FaucetSingleUntaggedACLTest(FaucetUntaggedTest):

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
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 5002
            actions:
                allow: 1 
        - rule:
            actions:
                allow: 1
"""

    def xtest_port5001_blocked(self):
        self.assertEquals(0, self.net.pingAll())
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        second_host.cmd('timeout 10s echo hello | nc -l 5001 &')
        self.assertEquals(
            '', first_host.cmd('timeout 10s nc %s 5001' % second_host.IP()))
        self.wait_until_matching_flow(r'"packet_count": [1-9]+.+"tp_dst": 5001')

    def test_port5002_unblocked(self):
        self.assertEquals(0, self.net.pingAll())
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        second_host.cmd('timeout 10s echo hello | nc -l %s 5002 &' % second_host.IP())
        time.sleep(1)
        self.wait_until_matching_flow(r'"packet_count": [1-9]+.+"tp_dst": 5002')
        self.assertEquals(
            'hello\r\n',
            first_host.cmd('nc -w 5 %s 5002' % second_host.IP()))
        self.wait_until_matching_flow(r'"packet_count": [1-9]+.+"tp_dst": 5002')


class FaucetSingleUntaggedACLMirrorTest(FaucetUntaggedTest):

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


class FaucetSingleUntaggedMirrorTest(FaucetUntaggedTest):

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
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_tagged=4)
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


class FaucetSingleTaggedIPv4RouteTest(FaucetTaggedTest):

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
            - route:
                ip_dst: "10.0.3.0/24"
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


class FaucetSingleUntaggedBGPIPv6RouteTest(FaucetUntaggedTest):

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
"""

    def test_untagged(self):
        exabgp_conf = """
group test {
  router-id 2.2.2.2;
  neighbor ::1 {
    passive;
    local-address ::1;
    peer-as 1;
    local-as 2;
    static {
      route fc00::10:1/112 next-hop fc00::1:1 local-preference 100;
      route fc00::20:1/112 next-hop fc00::1:2 local-preference 100;
      route fc00::30:1/112 next-hop fc00::1:2 local-preference 100;
    }
  }
}
"""
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="::1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> %s > %s &' % (exabgp_conf_file, exabgp_err, exabgp_log))
        self.verify_ipv6_routing_mesh()


class FaucetSingleUntaggedIPv6RouteTest(FaucetUntaggedTest):

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
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="::1" exabgp.tcp.port=179 exabgp '
            '%s -d 2> %s > %s &' % (exabgp_conf_file, exabgp_err, exabgp_log))
        self.verify_ipv6_routing_mesh()
        # exabgp should have received our BGP updates
        for _ in range(30):
            updates = controller.cmd(
                r'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                break
            time.sleep(1)
        assert re.search('fc00::1:0/112 next-hop fc00::1:254', updates)
        assert re.search('fc00::10:0/112 next-hop fc00::1:1', updates)
        assert re.search('fc00::20:0/112 next-hop fc00::1:2', updates)
        assert re.search('fc00::30:0/112 next-hop fc00::1:2', updates)


class FaucetSingleTaggedIPv6RouteTest(FaucetTaggedTest):

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
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.wait_until_matching_flow('fc00::20:')
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.swap_host_macs(first_host, second_host)
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
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


def check_dependencies():
    for (binary, binary_get_version, binary_present_re,
         binary_version_re, binary_minversion) in EXTERNAL_DEPENDENCIES:
        binary_args = [binary] + binary_get_version
        required_binary = 'required binary/library %s' % (
            ' '.join(binary_args))
        try:
            proc = subprocess.Popen(
                binary_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            proc_out, proc_err = proc.communicate()
            binary_output = proc_out
            if proc_err is not None:
                binary_output += proc_err
        except subprocess.CalledProcessError:
            # Might have run successfully, need to parse output
            pass
        except OSError:
            print 'could not run %s' % required_binary
            return False
        present_match = re.search(binary_present_re, binary_output)
        if not present_match:
            print '%s not present or did not return expected string %s' % (
                required_binary, binary_present_re)
            return False
        if binary_version_re:
            version_match = re.search(binary_version_re, binary_output)
            if version_match is None:
                print 'could not get version from %s (%s)' % (
                    required_binary, binary_output)
                return False
            try:
                binary_version = float(version_match.group(1))
            except ValueError:
                print 'cannot parse version %s for %s' % (
                    version_match, required_binary)
                return False
            if binary_version < binary_minversion:
                print '%s version %.1f is less than required version %.1f' % (
                    required_binary, binary_version, binary_minversion)
                return False
            print '%s version is %.1f' % (required_binary, binary_version)
        else:
            print '%s present (%s)' % (required_binary, binary_present_re)
    return True


def lint_check():
    for faucet_src in FAUCET_LINT_SRCS:
        faucet_src_path = os.path.join(FAUCET_DIR, faucet_src)
        ret = subprocess.call(['pylint', '-E', faucet_src_path])
        if ret:
            print 'lint of %s returns an error' % faucet_src
            return False
    return True


def make_suite(tc_class):
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(name))
    return suite


def run_tests():
    requested_test_classes = sys.argv[1:]
    single_tests = unittest.TestSuite()
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if not inspect.isclass(obj):
            continue
        if requested_test_classes and name not in requested_test_classes:
            continue
        if name.endswith('Test') and name.startswith('Faucet'):
            print 'adding test %s' % name
            if SWITCH_MAP or name.startswith('FaucetSingle'):
                single_tests.addTest(make_suite(obj))
            else:
                parallel_tests.addTest(make_suite(obj))
    print 'running %u tests in parallel and %u tests serial' % (
        parallel_tests.countTestCases(), single_tests.countTestCases())
    results = []
    if parallel_tests.countTestCases():
        max_parallel_tests = max(parallel_tests.countTestCases(), MAX_PARALLEL_TESTS)
        parallel_runner = unittest.TextTestRunner()
        parallel_suite = ConcurrentTestSuite(
            parallel_tests, fork_for_tests(max_parallel_tests))
        results.append(parallel_runner.run(parallel_suite))
    # TODO: Tests that are serialized generally depend on hardcoded ports.
    # Make them use dynamic ports.
    if single_tests.countTestCases():
        single_runner = unittest.TextTestRunner()
        results.append(single_runner.run(single_tests))
    for result in results:
       if not result.wasSuccessful():
           print result.printErrors()


if __name__ == '__main__':
    if not check_dependencies():
        print ('dependency check failed. check required library/binary '
               'list in header of this script')
        sys.exit(-1)
    if not lint_check():
        print 'pylint must pass with no errors'
        sys.exit(-1)
    import_config()
    run_tests()
