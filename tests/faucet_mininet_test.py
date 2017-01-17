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
# * curl

import glob
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
from mininet.clean import Cleanup
from ryu.ofproto import ofproto_v1_3 as ofp


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
    ('curl', ['--version'], 'libcurl',
     r'curl (\d+\.\d+).\d+', float(7.3)),
)

FAUCET_DIR = os.getenv('FAUCET_DIR', '../src/ryu_faucet/org/onfsdn/faucet')

# Must pass with 0 lint errors
FAUCET_LINT_SRCS = glob.glob(os.path.join(FAUCET_DIR, '*py'))

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
    while True:
        free_socket = socket.socket()
        free_socket.bind(('', 0))
        free_port = free_socket.getsockname()[1]
        free_socket.close()
        # ports reserved in tests
        if free_port not in [5001, 5002]:
            break
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
    CONFIG_GLOBAL = ''
    BOGUS_MAC = '01:02:03:04:05:06'

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        os.environ['FAUCET_CONFIG'] = os.path.join(
            self.tmpdir, 'faucet.yaml')
        os.environ['GAUGE_CONFIG'] = os.path.join(
            self.tmpdir, 'gauge.yaml')
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
                '\n'.join((self.CONFIG_GLOBAL,
                           'ofchannel_log: "%s"' % self.debug_log_path)),
                self.dpid, HARDWARE),
            self.CONFIG % PORT_MAP))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.GAUGE_CONFIG = self.get_gauge_config(
            self.dpid,
            os.environ['FAUCET_CONFIG'],
            self.monitor_ports_file,
            self.monitor_flow_table_file
            )
        open(os.environ['GAUGE_CONFIG'], 'w').write(self.GAUGE_CONFIG)
        self.net = None
        self.topo = None

    def get_gauge_config(self, dp_id, faucet_config_file,
                         monitor_ports_file, monitor_flow_table_file):
        return '''
faucet_configs:
    - {0}
watchers:
    port_stats:
        dps: ['faucet-1']
        type: 'port_stats'
        interval: 5
        db: 'ps_file'
    flow_table:
        dps: ['faucet-1']
        type: 'flow_table'
        interval: 5
        db: 'ft_file'
dbs:
    ps_file:
        type: 'text'
        file: {2}
    ft_file:
        type: 'text'
        file: {3}
'''.format(
    faucet_config_file,
    dp_id,
    monitor_ports_file,
    monitor_flow_table_file
    )

    def get_config_header(self, config_global, dpid, hardware):
        return '''
version: 2
%s
dps:
    faucet-1:
        dp_id: %s
        hardware: "%s"
''' % (config_global, str_int_dpid(dpid), hardware)

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

    def add_host_ipv6_route(self, host, ip_dst, ip_gw):
        host.cmd('ip -6 route add %s via %s' % (ip_dst.masked(), ip_gw))

    def one_ipv4_ping(self, host, dst):
        self.require_host_learned(host)
        ping_result = host.cmd('ping -c1 %s' % dst)
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv4_controller_ping(self, host):
        self.one_ipv4_ping(host, self.CONTROLLER_IPV4)

    def one_ipv6_ping(self, host, dst, timeout=2):
        self.require_host_learned(host)
        # TODO: retry our one ping. We should not have to retry.
        for _ in range(timeout):
            ping_result = host.cmd('ping6 -c1 %s' % dst)
            if re.search(self.ONE_GOOD_PING, ping_result):
                return
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv6_controller_ping(self, host):
        self.one_ipv6_ping(host, self.CONTROLLER_IPV6)

    def hup_faucet(self):
        controller = self.net.controllers[0]
        tcp_pattern = '%s/tcp' % controller.port
        fuser_out = controller.cmd('fuser %s -k -1' % tcp_pattern)
        self.assertTrue(re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out))

    def force_faucet_reload(self):
        # Force FAUCET to reload by adding new line to config file.
        open(os.environ['FAUCET_CONFIG'], 'a').write('\n')
        self.hup_faucet()

    def tcpdump_helper(self, tcpdump_host, tcpdump_filter, funcs=[],
                       timeout=10, packets=2):
        tcpdump_out = tcpdump_host.popen(
            'timeout %us tcpdump -e -n -U -v -c %u %s' % (
                timeout, packets, tcpdump_filter),
            stderr=subprocess.STDOUT)
        popens = {tcpdump_host: tcpdump_out}
        tcpdump_started = False
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == tcpdump_host:
                if tcpdump_started:
                    tcpdump_txt += line.strip()
                else:
                    # when we see tcpdump start, then call provided functions.
                    if re.search('tcpdump: listening on ', line):
                        tcpdump_started = True
                        for func in funcs:
                            func()
        return tcpdump_txt

    def bogus_mac_flooded_to_port1(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        first_host_mac = first_host.MAC()
        unicast_flood_filter = 'ether host %s' % self.BOGUS_MAC
        tcpdump_txt = self.tcpdump_helper(
            first_host, unicast_flood_filter,
                [lambda: second_host.cmd(
                     'arp -s %s %s' % (first_host.IP(), self.BOGUS_MAC)),
                 lambda: second_host.cmd(
                     'curl -m 5 http://%s' % first_host.IP()),
                 lambda: self.net.ping(hosts=(second_host, third_host))])
        return not re.search('0 packets captured', tcpdump_txt)

    def ofctl_rest_url(self):
        return 'http://127.0.0.1:%u' % self.net.controllers[0].ofctl_port

    def get_all_flows_from_dpid(self, dpid, timeout=10):
        int_dpid = str_int_dpid(dpid)
        for _ in range(timeout):
            try:
                ofctl_result = json.loads(requests.get(
                    '%s/stats/flow/%s' % (self.ofctl_rest_url(), int_dpid)).text)
            except (ValueError, requests.exceptions.ConnectionError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
            flow_dump = ofctl_result[int_dpid]
            return [json.dumps(flow) for flow in flow_dump]
        return []

    def matching_flow_present_on_dpid(self, dpid, exp_flow, timeout=10):
        for _ in range(timeout):
            flow_dump = self.get_all_flows_from_dpid(dpid, timeout)
            for flow in flow_dump:
                if re.search(exp_flow, flow):
                    return True
            time.sleep(1)
        return False

    def get_group_id_for_matching_flow(self, exp_flow, timeout=10):
        for _ in range(timeout):
            flow_dump = self.get_all_flows_from_dpid(self.dpid, timeout)
            for flow in flow_dump:
                if re.search(exp_flow, flow):
                    flow = json.loads(flow)
                    group_id = int(re.findall(r'\d+', str(flow['actions']))[0])
                    return group_id
            time.sleep(1)
        self.assertTrue(False,
                "Can't find group_id for matching flow %s" % exp_flow)

    def wait_matching_in_group_table(self, exp_flow, group_id, timeout=5):
        exp_group = '%s.+"group_id": %d' % (exp_flow, group_id)
        for _ in range(timeout):
            group_dump = self.get_all_groups_desc_from_dpid(self.dpid, 1)
            for group_desc in group_dump:
                if re.search(exp_group, group_desc):
                    return True
            time.sleep(1)
        return False

    def get_all_groups_desc_from_dpid(self, dpid, timeout=2):
        int_dpid = str_int_dpid(dpid)
        for _ in range(timeout):
            try:
                ofctl_result = json.loads(requests.get(
                    '%s/stats/groupdesc/%s' % (self.ofctl_rest_url(),
                                               int_dpid)).text)
                flow_dump = ofctl_result[int_dpid]
                return [json.dumps(flow) for flow in flow_dump]
            except (ValueError, requests.exceptions.ConnectionError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
        return []

    def matching_flow_present(self, exp_flow, timeout=10):
        return self.matching_flow_present_on_dpid(self.dpid, exp_flow, timeout)

    def wait_until_matching_flow(self, exp_flow, timeout=10):
        self.assertTrue(self.matching_flow_present(exp_flow, timeout)), exp_flow

    def host_learned(self, host):
        return self.matching_flow_present(
            '"table_id": 2,.+"dl_src": "%s"' % host.MAC())

    def require_host_learned(self, host):
        self.assertTrue(self.host_learned(host)), host

    def ping_all_when_learned(self):
        # Cause hosts to send traffic that FAUCET can use to learn them.
        self.net.pingAll()
        # we should have learned all hosts now, so should have no loss.
        for host in self.net.hosts:
            self.require_host_learned(host)
        self.assertEquals(0, self.net.pingAll())

    def wait_until_matching_route_as_flow(self, nexthop, prefix, timeout=5,
            with_group_table=False):
        if prefix.version == 6:
            exp_prefix = '/'.join(
                (str(prefix.masked().ip), str(prefix.netmask)))
            nw_dst_match = '"ipv6_dst": "%s"' % exp_prefix
        else:
            exp_prefix = prefix.masked().with_netmask
            nw_dst_match = '"nw_dst": "%s"' % exp_prefix
        if with_group_table:
            group_id = self.get_group_id_for_matching_flow(nw_dst_match)
            self.wait_matching_in_group_table('SET_FIELD: {eth_dst:%s}' % nexthop,
                    group_id, timeout)
        else:
            self.wait_until_matching_flow(
                'SET_FIELD: {eth_dst:%s}.+%s' % (nexthop, nw_dst_match), timeout)

    def curl_portmod(self, int_dpid, port_no, config, mask):
        # TODO: avoid dependency on varying 'requests' library.
        curl_format = ' '.join((
            'curl -X POST -d'
            '\'{"dpid": %s, "port_no": %u, "config": %u, "mask": %u}\'',
            '%s/stats/portdesc/modify'))
        return curl_format  % (
            int_dpid, port_no, config, mask, self.ofctl_rest_url())

    def flap_all_switch_ports(self, flap_time=1):
        # TODO: for hardware switches also
        if not SWITCH_MAP:
            switch = self.net.switches[0]
            int_dpid = str_int_dpid(self.dpid)
            for port_no in sorted(switch.ports.itervalues()):
                if port_no > 0:
                    os.system(self.curl_portmod(
                        int_dpid, port_no,
                        ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN))
                    time.sleep(flap_time)
                    os.system(self.curl_portmod(
                        int_dpid, port_no,
                        0, ofp.OFPPC_PORT_DOWN))

    def swap_host_macs(self, first_host, second_host):
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def verify_tp_dst_blocked(self, port, first_host, second_host):
        second_host.cmd('timeout 10s echo hello | nc -l %u &' % port)
        self.assertEquals(
            '', first_host.cmd('timeout 10s nc %s %u' % (second_host.IP(), port)))
        self.wait_until_matching_flow(
            r'"packet_count": [1-9]+.+"tp_dst": %u' % port)

    def verify_tp_dst_notblocked(self, port, first_host, second_host):
        second_host.cmd(
            'timeout 10s echo hello | nc -l %s %u &' % (second_host.IP(), port))
        time.sleep(1)
        self.assertEquals(
            'hello\r\n',
            first_host.cmd('nc -w 5 %s %u' % (second_host.IP(), port)))
        self.wait_until_matching_flow(
            r'"packet_count": [1-9]+.+"tp_dst": %u' % port)

    def add_host_ipv4_route(self, host, ip_dst, ip_gw):
        host.cmd('route add -net %s gw %s' % (ip_dst.masked(), ip_gw))

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip,
                            with_group_table=False):
        first_host.cmd(('ifconfig %s:0 %s netmask %s up' % (
            first_host.intf(),
            first_host_routed_ip.ip,
            first_host_routed_ip.netmask)))
        second_host.cmd(('ifconfig %s:0 %s netmask %s up' % (
            second_host.intf(),
            second_host_routed_ip.ip,
            second_host_routed_ip.netmask)))
        self.add_host_ipv4_route(
            first_host, second_host_routed_ip, self.CONTROLLER_IPV4)
        self.add_host_ipv4_route(
            second_host, first_host_routed_ip, self.CONTROLLER_IPV4)
        self.net.ping(hosts=(first_host, second_host))
        self.wait_until_matching_route_as_flow(
                first_host.MAC(), first_host_routed_ip,
                with_group_table=with_group_table)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), second_host_routed_ip,
            with_group_table=with_group_table)
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv4_routing_mesh(self, with_group_table=False):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        second_host_routed_ip2 = ipaddr.IPv4Network('10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2,
            with_group_table=with_group_table)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2,
            with_group_table=with_group_table)

    def setup_ipv6_hosts_addresses(self, first_host, first_host_ip,
                                   first_host_routed_ip, second_host,
                                   second_host_ip, second_host_routed_ip):
        for host in first_host, second_host:
            host.cmd('ip addr flush dev %s' % host.intf())
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip)
        self.add_host_ipv6_address(second_host, second_host_routed_ip)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip,
                            with_group_table=False):
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.add_host_ipv6_route(
            first_host, second_host_routed_ip, self.CONTROLLER_IPV6)
        self.add_host_ipv6_route(
            second_host, first_host_routed_ip, self.CONTROLLER_IPV6)
        self.wait_until_matching_route_as_flow(
            first_host.MAC(), first_host_routed_ip,
            with_group_table=with_group_table)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), second_host_routed_ip,
            with_group_table=with_group_table)
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv6_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv6_routing_pair(self, first_host, first_host_ip,
                                 first_host_routed_ip, second_host,
                                 second_host_ip, second_host_routed_ip,
                                 with_group_table=False):
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=with_group_table)

    def verify_ipv6_routing_mesh(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        second_host_routed_ip2 = ipaddr.IPv6Network('fc00::30:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)

    def stop_exabgp(self, port=179):
        controller = self.net.controllers[0]
        controller.cmd('fuser %s/tcp -k -9' % port)

    def start_exabgp(self, exabgp_conf, listen_address='127.0.0.1', port=179):
        self.stop_exabgp(port)
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.net.controllers[0]
        controller.cmd(
            'env exabgp.tcp.bind="%s" exabgp.tcp.port=%u '
            'timeout -s9 180s stdbuf -o0 -e0 exabgp %s -d 2> %s > %s &' % (
                listen_address, port, exabgp_conf_file, exabgp_err, exabgp_log))
        for _ in range(60):
            netstat = controller.cmd('netstat -an|grep %s:%s|grep ESTAB' % (
                listen_address, port))
            if netstat.find('ESTAB') > -1:
                return exabgp_log
            time.sleep(1)
        self.assertTrue(False)

    def exabgp_updates(self, exabgp_log):
        controller = self.net.controllers[0]
        # exabgp should have received our BGP updates
        for _ in range(60):
            updates = controller.cmd(
                r'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                return updates
            time.sleep(1)
        self.assertTrue(False)


class FaucetUntaggedTest(FaucetTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

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
"""

    def setUp(self):
        super(FaucetUntaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_untagged=4)
        self.start_net()

    def test_untagged(self):
        self.ping_all_when_learned()
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

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "mixed"
"""

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
"""

    def setUp(self):
        super(FaucetTaggedAndUntaggedVlanTest, self).setUp()
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_tagged=1, n_untagged=3)
        self.start_net()

    def test_untagged(self):
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


class FaucetUntaggedMaxHostsTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        max_hosts: 2
"""

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
"""

    def test_untagged(self):
        self.force_faucet_reload()
        self.net.pingAll()
        learned_hosts = [
            host for host in self.net.hosts if self.host_learned(host)]
        self.assertEquals(2, len(learned_hosts))


class FaucetUntaggedHUPTest(FaucetUntaggedTest):

    def get_configure_count(self):
        controller = self.net.controllers[0]
        configure_count = controller.cmd(
            'grep -c "configuration is unchanged" %s' % os.environ['FAUCET_LOG'])
        return configure_count

    def test_untagged(self):
        controller = self.net.controllers[0]
        switch = self.net.switches[0]
        for i in range(0, 3):
            configure_count = self.get_configure_count()
            self.assertEquals(i, int(configure_count))
            self.hup_faucet()
            time.sleep(1)
            for retry in range(3):
                configure_count = self.get_configure_count()
                if configure_count == i + 1:
                    break
                time.sleep(1)
            self.assertTrue(i + 1, configure_count)
            self.assertTrue(switch.connected())
            self.wait_until_matching_flow('OUTPUT:CONTROLLER')
            self.ping_all_when_learned()


class FaucetUntaggedHUPConfigChangeTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 53
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
"""
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
"""

    def get_flow(self, exp_flow, timeout=10):
        for _ in range(timeout):
            flow_dump = self.get_all_flows_from_dpid(self.dpid)
            for flow in flow_dump:
                if re.search(exp_flow, flow):
                    return json.loads(flow)
            time.sleep(1)
        return {}

    def ntest_change_port_vlan(self):
        self.ping_all_when_learned()
        conf = yaml.load(self.CONFIG)
        vid = 100
        for _ in range(1, 2):
            time.sleep(2)
            flow_p1 = self.get_flow(
                    '"table_id": 0, "match": {"dl_vlan": "0x0000", "in_port": 1}')
            flow_p3 = self.get_flow(
                    '"table_id": 0, "match": {"dl_vlan": "0x0000", "in_port": 3}')
            prev_dur_p1 = flow_p1['duration_sec']
            prev_dur_p3 = flow_p3['duration_sec']
            if vid == 200:
                vid = 100
                ping_test = self.ping_all_when_learned
            else:
                vid = 200
                ping_test = self.ping_cross_vlans
            conf['dps']['faucet-1']['interfaces'][1]['native_vlan'] = vid
            conf['dps']['faucet-1']['interfaces'][2]['native_vlan'] = vid
            open(os.environ['FAUCET_CONFIG'], 'w').write(yaml.dump(conf))
            self.hup_faucet()
            flow_p1 = self.get_flow(
                    '"table_id": 0, "match": {"dl_vlan": "0x0000", "in_port": 1}')
            flow_p3 = self.get_flow(
                    '"table_id": 0, "match": {"dl_vlan": "0x0000", "in_port": 3}')
            actions = flow_p1.get('actions', '')
            actions = [act for act in actions if 'vlan_vid' in act]
            vid_ = re.findall(r'\d+', str(actions))
            self.assertEqual(vid+4096, int(vid_[0]))
            dur_p1 = flow_p1['duration_sec']
            dur_p3 = flow_p3['duration_sec']
            self.assertGreater(prev_dur_p1, dur_p1)
            self.assertLess(prev_dur_p3, dur_p3)
            ping_test()

    def test_change_port_acl(self):
        self.ping_all_when_learned()
        conf = yaml.load(self.CONFIG)
        for i in range(1, 2):
            time.sleep(2)
            conf['acls'][1].insert(0,
                    {'rule': {'dl_type': 0x800,
                              'nw_proto': 17,
                              'tp_dst': 8000+i,
                              'actions': {'allow': 1}}})
            open(os.environ['FAUCET_CONFIG'], 'w').write(yaml.dump(conf))
            self.hup_faucet()
            self.wait_until_matching_flow(
                    '{"dl_type": 2048, "nw_proto": 17, "in_port": 1, "tp_dst": %d}' % \
                            (8000+i))

    def ping_cross_vlans(self):
        self.assertEqual(0, self.net.ping((self.net.hosts[0], self.net.hosts[1])))
        self.assertEqual(0, self.net.ping((self.net.hosts[2], self.net.hosts[3])))
        self.assertEqual(100, self.net.ping((self.net.hosts[0], self.net.hosts[3])))

class FaucetSingleUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
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
        first_host, second_host = self.net.hosts[:2]
        # wait until 10.0.0.1 has been resolved
        self.wait_until_matching_route_as_flow(
            first_host.MAC(), ipaddr.IPv4Network('10.99.99.0/24'))
        self.start_exabgp(exabgp_conf)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), ipaddr.IPv4Network('10.0.3.0/24'), timeout=30)
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        self.stop_exabgp()


class FaucetSingleUntaggedIPv4RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
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
        exabgp_log = self.start_exabgp(exabgp_conf)
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        # exabgp should have received our BGP updates
        updates = self.exabgp_updates(exabgp_log)
        self.stop_exabgp()
        assert re.search('10.0.0.0/24 next-hop 10.0.0.254', updates)
        assert re.search('10.0.1.0/24 next-hop 10.0.0.1', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)


class FaucetUntaggedVLanUnicastFloodTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: True
"""

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
"""

    def test_untagged(self):
        self.assertTrue(self.bogus_mac_flooded_to_port1())
        # Unicast flooding rule for from port 1
        self.assertTrue(self.matching_flow_present(
            '"table_id": 6, "match": {"dl_vlan": "100", "in_port": 1}'))
        # Unicast flood rule exists that output to port 1
        self.assertTrue(self.matching_flow_present(
            '"OUTPUT:1".+"table_id": 6, "match": {"dl_vlan": "100", "in_port": .}'))


class FaucetUntaggedNoVLanUnicastFloodTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
"""

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
"""

    def test_untagged(self):
        self.assertFalse(self.bogus_mac_flooded_to_port1())
        # No unicast flooding rule for from port 1
        self.assertFalse(self.matching_flow_present(
            '"table_id": 6, "match": {"dl_vlan": "100", "in_port": 1}'))
        # No unicast flood rule exists that output to port 1
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:1".+"table_id": 6, "match": {"dl_vlan": "100", "in_port": .}'))


class FaucetUntaggedPortUnicastFloodTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                unicast_flood: True
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        # VLAN level config to disable flooding takes precedence,
        # cannot enable port-only flooding.
        self.assertFalse(self.bogus_mac_flooded_to_port1())
        # No unicast flooding rule for from port 1
        self.assertFalse(self.matching_flow_present(
            '"table_id": 6, "match": {"dl_vlan": "100", "in_port": 1}'))
        # No unicast flood rule exists that output to port 1
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:1".+"table_id": 6, "match": {"dl_vlan": "100", "in_port": .}'))


class FaucetUntaggedNoPortUnicastFloodTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: True
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                unicast_flood: False
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        self.assertFalse(self.bogus_mac_flooded_to_port1())
        # Unicast flood rule present for port 2, but NOT for port 1
        self.assertTrue(self.matching_flow_present(
            '"table_id": 6, "match": {"dl_vlan": "100", "in_port": 2}'))
        self.assertFalse(self.matching_flow_present(
            '"table_id": 6, "match": {"dl_vlan": "100", "in_port": 1}'))
        # Unicast flood rules present that output to port 2, but NOT to port 1
        self.assertTrue(self.matching_flow_present(
            '"OUTPUT:2".+"table_id": 6, "match": {"dl_vlan": "100", "in_port": .}'))
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:1".+"table_id": 6, "match": {"dl_vlan": "100", "in_port": .}'))


class FaucetUntaggedHostMoveTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        self.swap_host_macs(first_host, second_host)
        self.net.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.assertEquals(0, self.net.ping((first_host, second_host)))


class FaucetUntaggedHostPermanentLearnTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

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
"""

    def test_untagged(self):
        self.ping_all_when_learned()
        first_host, second_host, third_host = self.net.hosts[0:3]
        # 3rd host impersonates 1st, 3rd host breaks but 1st host still OK
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        # 3rd host stops impersonating, now everything fine again.
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned()


class FaucetUntaggedControlPlaneTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        controller_ips: ["10.0.0.254/24", "fc00::1:254/112"]
"""

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
"""

    def test_ping_controller(self):
        first_host, second_host = self.net.hosts[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        for _ in range(2):
            # Verify IPv4 and IPv6 connectivity between first two hosts.
            self.one_ipv4_ping(first_host, second_host.IP())
            self.one_ipv6_ping(first_host, 'fc00::1:2')
            # Verify first two hosts can ping controller over both IPv4 and IPv6
            for host in first_host, second_host:
                self.one_ipv4_controller_ping(host)
                self.one_ipv6_controller_ping(host)
            self.flap_all_switch_ports()


class FaucetTaggedAndUntaggedTest(FaucetTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
    101:
        description: "untagged"
"""

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


class FaucetUntaggedACLTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
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
"""

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetUntaggedACLMirrorTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
acls:
    1:
        - rule:
            actions:
                allow: 1
                mirror: mirrorport
"""

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
            mirrorport:
                number: %(port_3)d
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.net.hosts[0:3]
        first_host.cmd('ping -c1 %s' % second_host.IP())
        mirror_mac = mirror_host.MAC()
        tcpdump_filter = 'not ether src %s and icmp' % mirror_mac
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt))


class FaucetUntaggedACLMirrorDefaultAllowTest(FaucetUntaggedACLMirrorTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
acls:
    1:
        - rule:
            actions:
                mirror: mirrorport
"""

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
            mirrorport:
                number: %(port_3)d
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""


class FaucetUntaggedOutputTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
acls:
    1:
        - rule:
            dl_dst: "01:02:03:04:05:06"
            actions:
                output:
                    dl_dst: "06:06:06:06:06:06"
                    vlan_vid: 123
                    port: acloutport
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                acl_in: 1
            acloutport:
                number: %(port_2)d
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = ('icmp and ether dst 06:06:06:06:06:06')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1  %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 123', tcpdump_txt))


class FaucetUntaggedMirrorTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: False
"""

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
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.net.hosts[0:3]
        first_host.cmd('ping -c1 %s' % second_host.IP())
        mirror_mac = mirror_host.MAC()
        tcpdump_filter = 'not ether src %s and icmp' % mirror_mac
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd('ping -c1  %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt))


class FaucetTaggedTest(FaucetTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
"""

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
"""

    def setUp(self):
        super(FaucetTaggedTest, self).setUp()
        self.topo = FaucetSwitchTopo(dpid=self.dpid, n_tagged=4)
        self.start_net()

    def test_tagged(self):
        self.ping_all_when_learned()


class FaucetTaggedControlPlaneTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        controller_ips: ["10.0.0.254/24", "fc00::1:254/112"]
"""

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

    CONFIG_GLOBAL = """
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

    CONFIG_GLOBAL = """
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
        self.start_exabgp(exabgp_conf, '::1')
        self.verify_ipv6_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv6_routing_mesh()
        self.stop_exabgp()


class FaucetUntaggedSameVlanIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        controller_ips: ["fc00::10:1/112", "fc00::20:1/112"]
        routes:
            - route:
                ip_dst: "fc00::10:0/112"
                ip_gw: "fc00::10:2"
            - route:
                ip_dst: "fc00::20:0/112"
                ip_gw: "fc00::20:2"
"""

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
"""

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        first_host_ip = ipaddr.IPv6Network('fc00::10:2/112')
        first_host_ctrl_ip = ipaddr.IPv6Address('fc00::10:1')
        second_host_ip = ipaddr.IPv6Network('fc00::20:2/112')
        second_host_ctrl_ip = ipaddr.IPv6Address('fc00::20:1')
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_route(
            first_host, second_host_ip, first_host_ctrl_ip)
        self.add_host_ipv6_route(
            second_host, first_host_ip, second_host_ctrl_ip)
        self.wait_until_matching_route_as_flow(
            first_host.MAC(), first_host_ip)
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), second_host_ip)
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(first_host, second_host_ctrl_ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ctrl_ip)


class FaucetSingleUntaggedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
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
        exabgp_log = self.start_exabgp(exabgp_conf, '::1')
        self.verify_ipv6_routing_mesh()
        second_host = self.net.hosts[1]
        self.flap_all_switch_ports()
        self.wait_until_matching_route_as_flow(
            second_host.MAC(), ipaddr.IPv6Network('fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        updates = self.exabgp_updates(exabgp_log)
        self.stop_exabgp()
        assert re.search('fc00::1:0/112 next-hop fc00::1:254', updates)
        assert re.search('fc00::10:0/112 next-hop fc00::1:1', updates)
        assert re.search('fc00::20:0/112 next-hop fc00::1:2', updates)
        assert re.search('fc00::30:0/112 next-hop fc00::1:2', updates)


class FaucetSingleTaggedIPv6RouteTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
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
"""

    def test_tagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)


class FaucetStringOfDPSwitchTopo(Topo):

    def build(self, dpids, n_tagged=0, tagged_vid=100, n_untagged=0):
        """String of datapaths each with hosts with a single FAUCET controller.

                               Hosts
                               ||||
                               ||||
                 +----+       +----+       +----+
              ---+1   |       |1234|       |   1+---
        Hosts ---+2   |       |    |       |   2+--- Hosts
              ---+3   |       |    |       |   3+---
              ---+4  5+-------+5  6+-------+5  4+---
                 +----+       +----+       +----+

                 Faucet-1     Faucet-2     Faucet-3

                   |            |            |
                   |            |            |
                   +-------- controller -----+

        * s switches (above S = 3; for S > 3, switches are added to the chain)
        * (n_tagged + n_untagged) hosts per switch
        * (n_tagged + n_untagged + 1) links on switches 0 and s-1,
          with final link being inter-switch
        * (n_tagged + n_untagged + 2) links on switches 0 < n < s-1,
          with final two links being inter-switch
        """

        pid = os.getpid()
        switches = []

        for i, dpid in enumerate(dpids):
            hosts = []

            for host_n in range(n_tagged):
                host_name = 't%xs%ih%s' % (pid % 0xff, i + 1, host_n + 1)
                host = self.addHost(host_name, cls=VLANHost, vlan=tagged_vid)
                hosts.append(host)

            for host_n in range(n_untagged):
                host_name = 'u%xs%ih%s' % (pid % 0xff, i + 1, host_n + 1)
                host = self.addHost(host_name)
                hosts.append(host)

            switch_name = 's%i%x' % (i + 1, pid)
            switch = self.addSwitch(
                switch_name, cls=FaucetSwitch, listenPort=find_free_port(),
                dpid=dpid)

            for host in hosts:
                self.addLink(host, switch)

            # Add a switch-to-switch link with the previous switch,
            # if this isn't the first switch in the topology.
            if switches:
                self.addLink(switches[i - 1], switch)

            switches.append(switch)


class FaucetStringOfDPTest(FaucetTest):

    def build_net(self, n_dps=1, stack=False, n_tagged=0, tagged_vid=100,
                  n_untagged=0, untagged_vid=100,
                  include=[], include_optional=[], acls={}, acl_in_dp={}):
        """Set up Mininet and Faucet for the given topology."""

        self.dpids = [str(random.randint(1, 2**32)) for _ in range(n_dps)]

        self.topo = FaucetStringOfDPSwitchTopo(
            dpids=self.dpids,
            n_tagged=n_tagged,
            tagged_vid=tagged_vid,
            n_untagged=n_untagged,
        )

        self.CONFIG = self.get_config(
            self.dpids,
            stack,
            HARDWARE,
            self.debug_log_path,
            n_tagged,
            tagged_vid,
            n_untagged,
            untagged_vid,
            include,
            include_optional,
            acls,
            acl_in_dp,
        )
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)

    def get_config(self, dpids=[], stack=False, hardware=None, ofchannel_log=None,
                   n_tagged=0, tagged_vid=0, n_untagged=0, untagged_vid=0,
                   include=[], include_optional=[], acls={}, acl_in_dp={}):
        """Build a complete Faucet configuration for each datapath, using the given topology."""

        def dp_name(i):
            return 'faucet-%i' % (i + 1)

        def add_acl_to_port(name, p, interfaces_config):
            if name in acl_in_dp and p in acl_in_dp[name]:
                interfaces_config[p]['acl_in'] = acl_in_dp[name][p]

        config = {'version': 2}

        # Includes.
        if include:
            config['include'] = list(include)

        if include_optional:
            config['include-optional'] = list(include_optional)

        # Datapaths.
        if dpids:
            dpid_count = len(dpids)
            num_switch_links = None

            config['dps'] = {}

            for i, dpid in enumerate(dpids):
                p = 1
                name = dp_name(i)
                config['dps'][name] = {
                    'dp_id': int(str_int_dpid(dpid)),
                    'hardware': hardware,
                    'ofchannel_log': ofchannel_log,
                    'interfaces': {},
                }
                dp_config = config['dps'][name]
                interfaces_config = dp_config['interfaces']

                for _ in range(n_tagged):
                    interfaces_config[p] = {
                        'tagged_vlans': [tagged_vid],
                        'description': 'b%i' % p,
                    }
                    add_acl_to_port(name, p, interfaces_config)
                    p += 1

                for _ in range(n_untagged):
                    interfaces_config[p] = {
                        'native_vlan': untagged_vid,
                        'description': 'b%i' % p,
                    }
                    add_acl_to_port(name, p, interfaces_config)
                    p += 1

                # Add configuration for the switch-to-switch links
                # (0 for a single switch, 1 for an end switch, 2 for middle switches).
                first_dp = i == 0
                second_dp = i == 1
                last_dp = i == dpid_count - 1
                end_dp = first_dp or last_dp
                num_switch_links = 0
                if dpid_count > 1:
                    if end_dp:
                        num_switch_links = 1
                    else:
                        num_switch_links = 2

                if stack and first_dp:
                    dp_config['stack'] = {
                        'priority': 1
                    }

                first_stack_port = p

                for stack_dp_port in range(num_switch_links):
                    tagged_vlans = None

                    peer_dp = None
                    if stack_dp_port == 0:
                        if first_dp:
                            peer_dp = i + 1
                        else:
                            peer_dp = i - 1
                        if first_dp or second_dp:
                            peer_port = first_stack_port
                        else:
                            peer_port = first_stack_port + 1
                    else:
                        peer_dp = i + 1
                        peer_port = first_stack_port

                    description = 'to %s' % dp_name(peer_dp)

                    interfaces_config[p] = {
                        'description': description,
                    }

                    if stack:
                        interfaces_config[p]['stack'] = {
                            'dp': dp_name(peer_dp),
                            'port': peer_port,
                        }
                    else:
                        if n_tagged and n_untagged and n_tagged != n_untagged:
                            tagged_vlans = [tagged_vid, untagged_vid]
                        elif ((n_tagged and not n_untagged) or
                              (n_tagged and n_untagged and tagged_vid == untagged_vid)):
                            tagged_vlans = [tagged_vid]
                        elif n_untagged and not n_tagged:
                            tagged_vlans = [untagged_vid]

                        if tagged_vlans:
                            interfaces_config[p]['tagged_vlans'] = tagged_vlans

                    add_acl_to_port(name, p, interfaces_config)
                    # Used as the port number for the current switch.
                    p += 1

            # VLANs.
            config['vlans'] = {}

            if n_untagged:
                config['vlans'][untagged_vid] = {
                    'description': 'untagged',
                }

            if ((n_tagged and not n_untagged) or
                    (n_tagged and n_untagged and tagged_vid != untagged_vid)):
                config['vlans'][tagged_vid] = {
                    'description': 'tagged',
                }

        # ACLs.
        if acls:
            config['acls'] = acls.copy()

        return yaml.dump(config, default_flow_style=False)

    def matching_flow_present(self, exp_flow, timeout=10):
        """Find the first DP that has a flow that matches exp_flow."""

        for dpid in self.dpids:
            if self.matching_flow_present_on_dpid(dpid, exp_flow, timeout):
                return True
        return False


class FaucetStringOfDPUntaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3
    NUM_HOSTS = 4
    VID = 100

    def setUp(self):
        super(FaucetStringOfDPUntaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS, untagged_vid=self.VID)
        self.start_net()

    def test_untagged(self):
        self.assertEquals(0, self.net.pingAll())


class FaucetStringOfDPTaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3
    NUM_HOSTS = 4
    VID = 100

    def setUp(self):
        super(FaucetStringOfDPTaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, tagged_vid=self.VID)
        self.start_net()

    def test_tagged(self):
        self.assertEquals(0, self.net.pingAll())


class FaucetStackStringOfDPTaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3
    NUM_HOSTS = 4
    VID = 100

    def setUp(self):
        super(FaucetStackStringOfDPTaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, tagged_vid=self.VID,
            stack=True)
        self.start_net()

    def test_tagged(self):
        self.net.pingAll()
        # Distributed learning has had a chance to happen.
        self.assertEquals(0, self.net.pingAll())


class FaucetStringOfDPACLOverrideTest(FaucetStringOfDPTest):

    NUM_DPS = 1
    NUM_HOSTS = 2
    VID = 100

    # ACL rules which will get overridden.
    ACLS = {
        1: [
            {'rule': {
                'dl_type': int('0x800', 16),
                'nw_proto': 6,
                'tp_dst': 5001,
                'actions': {
                    'allow': 1,
                },
            }},
            {'rule': {
                'dl_type': int('0x800', 16),
                'nw_proto': 6,
                'tp_dst': 5002,
                'actions': {
                    'allow': 0,
                },
            }},
            {'rule': {
                'actions': {
                    'allow': 1,
                },
            }},
        ],
    }

    # ACL rules which get put into an include-optional
    # file, then reloaded into FAUCET.
    ACLS_OVERRIDE = {
        1: [
            {'rule': {
                'dl_type': int('0x800', 16),
                'nw_proto': 6,
                'tp_dst': 5001,
                'actions': {
                    'allow': 0,
                },
            }},
            {'rule': {
                'dl_type': int('0x800', 16),
                'nw_proto': 6,
                'tp_dst': 5002,
                'actions': {
                    'allow': 1,
                },
            }},
            {'rule': {
                'actions': {
                    'allow': 1,
                },
            }},
        ],
    }

    # DP-to-acl_in port mapping.
    ACL_IN_DP = {
        'faucet-1': {
            # Port 1, acl_in = 1
            1: 1,
        },
    }

    def setUp(self):
        super(FaucetStringOfDPACLOverrideTest, self).setUp()
        self.acls_config = os.path.join(self.tmpdir, 'acls.yaml')
        self.build_net(
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            untagged_vid=self.VID,
            include_optional=[self.acls_config],
            acls=self.ACLS,
            acl_in_dp=self.ACL_IN_DP,
        )
        self.start_net()

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(5001, first_host, second_host)
        open(self.acls_config, 'w').write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.hup_faucet()
        time.sleep(1)
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        open(self.acls_config, 'w').write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.hup_faucet()
        time.sleep(1)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetGroupTableTest(FaucetUntaggedTest):
    CONFIG = """
        group_table: True
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
"""

    def test_group_exist(self):
        self.assertEqual(100,
                self.get_group_id_for_matching_flow(
                    '"table_id": 6,.+"dl_vlan": "100"'))


class FaucetSingleUntaggedIPv4RouteGroupTableTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
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
    CONFIG = """
        arp_neighbor_timeout: 2
        group_table: True
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
"""

    def test_untagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=True)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=True)

class FaucetSingleUntaggedIPv6RouteGroupTableTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        controller_ips: ["fc00::1:254/112"]
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

    CONFIG = """
        arp_neighbor_timeout: 2
        group_table: True
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
"""

    def test_untagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=True)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=True)


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
            test_port_name = 'port_%u' % (i + 1)
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
        ret = subprocess.call(['pylint', '-E', faucet_src])
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
    if '-c' in sys.argv[1:] or '--clean' in sys.argv[1:]:
        print (
            'Cleaning up test interfaces, processes and openvswitch'
            'configuration from previous test runs')
        Cleanup.cleanup()
        sys.exit(0)
    if not check_dependencies():
        print ('dependency check failed. check required library/binary '
               'list in header of this script')
        sys.exit(-1)
    if not lint_check():
        print 'pylint must pass with no errors'
        sys.exit(-1)
    import_config()
    run_tests()
