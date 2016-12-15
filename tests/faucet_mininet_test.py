#!/usr/bin/python

"""Mininet tests for FAUCET.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest

 REQUIRES:

 * mininet 2.2.0 or later (Ubuntu 14 ships with 2.1.0, which is not supported)
   use the "install from source" option from
   https://github.com/mininet/mininet/blob/master/INSTALL.
   suggest ./util/install.sh -n
 * OVS 2.3.1 or later (Ubuntu 14 ships with 2.0.2, which is not supported)
 * VLAN utils (vconfig, et al - on Ubuntu, apt-get install vlan)
 * fuser
 * net-tools
 * iputils-ping
 * netcat-openbsd
 * tcpdump
 * exabgp
 * pylint
 * curl
"""

import glob
import inspect
import os
import sys
import getopt
import random
import re
import subprocess
import tempfile
import threading
import time
import unittest

import ipaddr
import yaml

from concurrencytest import ConcurrentTestSuite, fork_for_tests
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Intf
from mininet.util import dumpNodeConnections, pmonitor
from mininet.clean import Cleanup

import faucet_mininet_test_util
import faucet_mininet_test_base


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

# Must pass with 0 lint errors
FAUCET_LINT_SRCS = glob.glob(os.path.join(faucet_mininet_test_util.FAUCET_DIR, '*py'))

# Maximum number of parallel tests to run at once
MAX_PARALLEL_TESTS = 4

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
REQUIRED_TEST_PORTS = 4



class FaucetTest(faucet_mininet_test_base.FaucetTestBase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='faucettests')
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
        self.monitor_stats_file = os.path.join(
            self.tmpdir, 'ports.txt')
        self.monitor_state_file = os.path.join(
            self.tmpdir, 'state.txt')
        self.monitor_flow_table_file = os.path.join(
            self.tmpdir, 'flow.txt')
        if self.config is not None:
            if 'hw_switch' in self.config:
                self.hw_switch = self.config['hw_switch']
            if self.hw_switch:
                self.dpid = self.config['dpid']
                self.of_port = self.config['of_port']
                self.gauge_of_port = self.config['gauge_of_port']
                self.hardware = self.config['hardware']
                dp_ports = self.config['dp_ports']
                self.port_map = {}
                self.switch_map = {}
                for i, switch_port in enumerate(dp_ports):
                    test_port_name = 'port_%u' % (i + 1)
                    self.port_map[test_port_name] = switch_port
                    self.switch_map[test_port_name] = dp_ports[switch_port]

        if self.hw_switch:
            self.topo_class = faucet_mininet_test_base.FaucetHwSwitchTopo
            self.dpid = faucet_mininet_test_util.str_int_dpid(self.dpid)
        else:
            self.topo_class = faucet_mininet_test_base.FaucetSwitchTopo
            self.dpid = str(random.randint(1, 2**32))
            self.of_port, _ = faucet_mininet_test_util.find_free_port()
            self.gauge_of_port, _ = faucet_mininet_test_util.find_free_port()

        self.CONFIG = '\n'.join((
            self.get_config_header(
                self.CONFIG_GLOBAL, self.debug_log_path, self.dpid, self.hardware),
            self.CONFIG % self.port_map))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.GAUGE_CONFIG = self.get_gauge_config(
            os.environ['FAUCET_CONFIG'],
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file
            )
        open(os.environ['GAUGE_CONFIG'], 'w').write(self.GAUGE_CONFIG)
        self.net = None
        self.topo = None

    def attach_physical_switch(self):
        """Bridge a physical switch into test topology."""
        switch = self.net.switches[0]
        hosts_count = len(self.net.hosts)
        for i, test_host_port in enumerate(sorted(self.switch_map)):
            port_i = i + 1
            mapped_port_i = port_i + hosts_count
            phys_port = Intf(self.switch_map[test_host_port], node=switch)
            switch.cmd('ip link set dev %s up' % phys_port)
            switch.cmd('ovs-vsctl add-port %s %s' % (switch.name, phys_port.name))
            for port_pair in ((port_i, mapped_port_i), (mapped_port_i, port_i)):
                port_x, port_y = port_pair
                switch.cmd('%s add-flow %s in_port=%u,actions=output:%u' % (
                    self.OFCTL, switch.name, port_x, port_y))

    def start_net(self):
        """Start Mininet network."""
        self.net = Mininet(
            self.topo,
            controller=faucet_mininet_test_base.FAUCET(
                name='faucet', port=self.of_port))
        self.pre_start_net()
        gauge_controller = faucet_mininet_test_base.Gauge(
            name='gauge', port=self.gauge_of_port)
        self.net.addController(gauge_controller)
        self.net.start()
        if self.hw_switch:
            self.attach_physical_switch()
        self.net.waitConnected()
        self.wait_debug_log()
        self.wait_until_matching_flow('OUTPUT:CONTROLLER')
        dumpNodeConnections(self.net.hosts)

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
        unicast_flood_filter = 'ether host %s' % self.BOGUS_MAC
        static_bogus_arp = 'arp -s %s %s' % (first_host.IP(), self.BOGUS_MAC)
        curl_first_host = 'curl -m 5 http://%s' % first_host.IP()
        tcpdump_txt = self.tcpdump_helper(
            first_host, unicast_flood_filter,
            [lambda: second_host.cmd(static_bogus_arp),
             lambda: second_host.cmd(curl_first_host),
             lambda: self.net.ping(hosts=(second_host, third_host))])
        return not re.search('0 packets captured', tcpdump_txt)

    def verify_ping_mirrored(self, first_host, second_host, mirror_host):
        self.net.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.assertEquals(0, self.net.ping((first_host, second_host)))
        mirror_mac = mirror_host.MAC()
        tcpdump_filter = (
            'not ether src %s and '
            '(icmp[icmptype] == 8 or icmp[icmptype] == 0)') % mirror_mac
        first_ping_second = 'ping -c1 %s' % second_host.IP()
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd(first_ping_second)])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)

    def gauge_smoke_test(self):
        watcher_files = (
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file)
        for watcher_file in watcher_files:
            for _ in range(5):
                if os.path.exists(watcher_file):
                    break
                time.sleep(1)
            self.assertTrue(os.stat(watcher_file).st_size > 0)


class FaucetUntaggedTest(FaucetTest):
    """Basic untagged VLAN test."""

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
        self.topo = self.topo_class(dpid=self.dpid, n_untagged=4)
        self.start_net()

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.gauge_smoke_test()


class FaucetTaggedAndUntaggedVlanTest(FaucetTest):
    """Test mixture of tagged and untagged hosts on the same VLAN."""

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
        self.topo = self.topo_class(dpid=self.dpid, n_tagged=1, n_untagged=3)
        self.start_net()

    def test_untagged(self):
        """Test connectivity including after port flapping."""
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
        self.force_faucet_reload('       timeout: 60')
        self.net.pingAll()
        learned_hosts = [
            host for host in self.net.hosts if self.host_learned(host)]
        self.assertEquals(2, len(learned_hosts))


class FaucetUntaggedHUPTest(FaucetUntaggedTest):
    """Test handling HUP signal without config change."""

    def get_configure_count(self):
        """Return the number of times FAUCET has received HUP."""
        controller = self.net.controllers[0]
        configure_count = controller.cmd(
            'grep -c "configuration is unchanged" %s' % os.environ['FAUCET_LOG'])
        return configure_count

    def test_untagged(self):
        """Test that FAUCET receives HUP signal and keeps switching."""
        switch = self.net.switches[0]
        for i in range(0, 3):
            configure_count = self.get_configure_count()
            self.assertEquals(i, int(configure_count))
            self.hup_faucet()
            time.sleep(1)
            for _ in range(3):
                configure_count = self.get_configure_count()
                if configure_count == i + 1:
                    break
                time.sleep(1)
            self.assertTrue(i + 1, configure_count)
            self.assertTrue(switch.connected())
            self.wait_until_matching_flow('OUTPUT:CONTROLLER')
            self.ping_all_when_learned()


class FaucetUntaggedHUPConfigChangeTest(FaucetUntaggedTest):
    """Test handling HUP signal with config change."""

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

    def ntest_change_port_vlan(self):
        self.ping_all_when_learned()
        conf = yaml.load(self.CONFIG)
        vid = 100
        for _ in range(1, 2):
            time.sleep(2)
            flow_p1 = self.get_matching_flow_on_dpid(
                self.dpid,
                ('"table_id": 0, "match": '
                 '{"dl_vlan": "0x0000", "in_port": 1}'))
            flow_p3 = self.get_matching_flow_on_dpid(
                self.dpid,
                ('"table_id": 0, "match": '
                 '{"dl_vlan": "0x0000", "in_port": 3}'))
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
            flow_p1 = self.get_matching_flow_on_dpid(
                self.dpid,
                ('"table_id": 0, "match": '
                 '{"dl_vlan": "0x0000", "in_port": 1}'))
            flow_p3 = self.get_matching_flow_on_dpid(
                self.dpid,
                ('"table_id": 0, "match": '
                 '{"dl_vlan": "0x0000", "in_port": 3}'))
            actions = flow_p1.get('actions', '')
            actions = [act for act in actions if 'vlan_vid' in act]
            vid_ = re.findall(r'\d+', str(actions))
            self.assertEqual(vid+4096, int(vid_[0]))
            dur_p1 = flow_p1['duration_sec']
            dur_p3 = flow_p3['duration_sec']
            self.assertGreater(prev_dur_p1, dur_p1)
            self.assertLess(prev_dur_p3, dur_p3)
            ping_test()

    def ping_cross_vlans(self):
        self.assertEqual(0,
                         self.net.ping((self.net.hosts[0], self.net.hosts[1])))
        self.assertEqual(0,
                         self.net.ping((self.net.hosts[2], self.net.hosts[3])))
        self.assertEqual(100,
                         self.net.ping((self.net.hosts[0], self.net.hosts[3])))

    def test_change_port_acl(self):
        self.ping_all_when_learned()
        conf = yaml.load(self.CONFIG)
        for i in range(1, 2):
            time.sleep(2)
            conf['acls'][1].insert(
                0,
                {'rule': {'dl_type': 0x800,
                          'nw_proto': 17,
                          'tp_dst': 8000+i,
                          'actions': {'allow': 1}}})
            open(os.environ['FAUCET_CONFIG'], 'w').write(yaml.dump(conf))
            self.hup_faucet()
            self.wait_until_matching_flow(
                ('{"dl_type": 2048, "nw_proto": 17,'
                 ' "in_port": 1, "tp_dst": %d}' % (8000+i)))


class FaucetSingleUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import from BGP."""

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
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        first_host, second_host = self.net.hosts[:2]
        # wait until 10.0.0.1 has been resolved
        self.wait_for_route_as_flow(
            first_host.MAC(), ipaddr.IPv4Network('10.99.99.0/24'))
        self.wait_bgp_up(self.exabgp_log)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddr.IPv4Network('10.0.3.0/24'))
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        self.stop_exabgp()


class FaucetSingleUntaggedIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and export to BGP."""

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
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes sent."""
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        self.wait_bgp_up(self.exabgp_log)
        # exabgp should have received our BGP updates
        updates = self.exabgp_updates(self.exabgp_log)
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
        self.topo = self.topo_class(dpid=self.dpid, n_tagged=2, n_untagged=2)
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
        self.verify_ping_mirrored(first_host, second_host, mirror_host)


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
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
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
        self.verify_ping_mirrored(first_host, second_host, mirror_host)


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
        self.topo = self.topo_class(dpid=self.dpid, n_tagged=4)
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


class FaucetTaggedIPv4RouteTest(FaucetTaggedTest):

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


class FaucetUntaggedMixedIPv4RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        controller_ips: ["172.16.0.254/24", "10.0.0.254/24"]
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
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddr.IPv4Network('10.0.0.1/24')
        second_host_net = ipaddr.IPv4Network('172.16.0.1/24')
        second_host.setIP(str(second_host_net.ip))
        self.one_ipv4_ping(first_host, self.CONTROLLER_IPV4.ip)
        self.one_ipv4_ping(second_host, self.CONTROLLER_IPV4_2.ip)
        self.add_host_ipv4_route(
            first_host, second_host_net.masked(), self.CONTROLLER_IPV4.ip)
        self.add_host_ipv4_route(
            second_host, first_host_net.masked(), self.CONTROLLER_IPV4_2.ip)
        self.one_ipv4_ping(first_host, second_host_net.ip)
        self.one_ipv4_ping(second_host, first_host_net.ip)


class FaucetUntaggedMixedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        controller_ips: ["fc00::1:254/64", "fc01::1:254/64"]
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
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddr.IPv6Network('fc00::1:1/64')
        second_host_net = ipaddr.IPv6Network('fc01::1:1/64')
        self.add_host_ipv6_address(first_host, first_host_net)
        self.one_ipv6_ping(first_host, self.CONTROLLER_IPV6.ip)
        self.add_host_ipv6_address(second_host, second_host_net)
        self.one_ipv6_ping(second_host, self.CONTROLLER_IPV6_2.ip)
        self.add_host_ipv6_route(
            first_host, second_host_net.masked(), self.CONTROLLER_IPV6.ip)
        self.add_host_ipv6_route(
            second_host, first_host_net.masked(), self.CONTROLLER_IPV6_2.ip)
        self.one_ipv6_ping(first_host, second_host_net.ip)
        self.one_ipv6_ping(second_host, first_host_net.ip)


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
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf, '::1')

    def test_untagged(self):
        self.wait_bgp_up(self.exabgp_log)
        self.wait_exabgp_sent_updates(self.exabgp_log)
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
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_ip)
        self.wait_for_route_as_flow(
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
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf, '::1')

    def test_untagged(self):
        self.verify_ipv6_routing_mesh()
        second_host = self.net.hosts[1]
        self.flap_all_switch_ports()
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddr.IPv6Network('fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        self.wait_bgp_up(self.exabgp_log)
        updates = self.exabgp_updates(self.exabgp_log)
        self.stop_exabgp()
        assert re.search('fc00::1:0/112 next-hop fc00::1:254', updates)
        assert re.search('fc00::10:0/112 next-hop fc00::1:1', updates)
        assert re.search('fc00::20:0/112 next-hop fc00::1:2', updates)
        assert re.search('fc00::30:0/112 next-hop fc00::1:2', updates)


class FaucetTaggedIPv6RouteTest(FaucetTaggedTest):
    """Test basic IPv6 routing without BGP."""

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
        """Test IPv6 routing works."""
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


class FaucetStringOfDPSwitchTopo(faucet_mininet_test_base.FaucetSwitchTopo):

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
        last_switch = None
        for dpid in dpids:
            port, ports_served = faucet_mininet_test_util.find_free_port()
            sid_prefix = self._get_sid_prefix(ports_served)
            hosts = []
            for host_n in range(n_tagged):
                hosts.append(self._add_tagged_host(sid_prefix, tagged_vid, host_n))
            for host_n in range(n_untagged):
                hosts.append(self._add_untagged_host(sid_prefix, host_n))
            switch = self._add_faucet_switch(sid_prefix, port, dpid)
            for host in hosts:
                self.addLink(host, switch)
            # Add a switch-to-switch link with the previous switch,
            # if this isn't the first switch in the topology.
            if last_switch is not None:
                self.addLink(last_switch, switch)
            last_switch = switch


class FaucetStringOfDPTest(FaucetTest):

    NUM_HOSTS = 4
    VID = 100
    dpids = None

    def build_net(self, stack=False, n_dps=1,
                  n_tagged=0, tagged_vid=100,
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
            self.hardware,
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

        def add_vlans(n_tagged, tagged_vid, n_untagged, untagged_vid):
            vlans_config = {}
            if n_untagged:
                vlans_config[untagged_vid] = {
                    'description': 'untagged',
                }

            if ((n_tagged and not n_untagged) or
                    (n_tagged and n_untagged and tagged_vid != untagged_vid)):
                vlans_config[tagged_vid] = {
                    'description': 'tagged',
                }
            return vlans_config

        def add_acl_to_port(name, port, interfaces_config):
            if name in acl_in_dp and port in acl_in_dp[name]:
                interfaces_config[port]['acl_in'] = acl_in_dp[name][port]

        def add_dp_to_dp_ports(dp_config, port, interfaces_config, i,
                               dpid_count, stack, n_tagged, tagged_vid,
                               n_untagged, untagged_vid):
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

            first_stack_port = port

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

                interfaces_config[port] = {
                    'description': description,
                }

                if stack:
                    interfaces_config[port]['stack'] = {
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
                        interfaces_config[port]['tagged_vlans'] = tagged_vlans

                add_acl_to_port(name, port, interfaces_config)
                port += 1

        def add_dp(name, dpid, i, dpid_count, stack,
                   n_tagged, tagged_vid, n_untagged, untagged_vid):
            dpid_ofchannel_log = ofchannel_log + str(i)
            dp_config = {
                'dp_id': int(dpid),
                'hardware': hardware,
                'ofchannel_log': dpid_ofchannel_log,
                'interfaces': {},
            }
            interfaces_config = dp_config['interfaces']

            port = 1
            for _ in range(n_tagged):
                interfaces_config[port] = {
                    'tagged_vlans': [tagged_vid],
                    'description': 'b%i' % port,
                }
                add_acl_to_port(name, port, interfaces_config)
                port += 1

            for _ in range(n_untagged):
                interfaces_config[port] = {
                    'native_vlan': untagged_vid,
                    'description': 'b%i' % port,
                }
                add_acl_to_port(name, port, interfaces_config)
                port += 1

            add_dp_to_dp_ports(
                dp_config, port, interfaces_config, i, dpid_count, stack,
                n_tagged, tagged_vid, n_untagged, untagged_vid)

            return dp_config

        config = {'version': 2}

        if include:
            config['include'] = list(include)

        if include_optional:
            config['include-optional'] = list(include_optional)

        config['vlans'] = add_vlans(
            n_tagged, tagged_vid, n_untagged, untagged_vid)

        config['acls'] = acls.copy()

        dpid_count = len(dpids)
        config['dps'] = {}

        for i, dpid in enumerate(dpids):
            name = dp_name(i)
            config['dps'][name] = add_dp(
                name, dpid, i, dpid_count, stack,
                n_tagged, tagged_vid, n_untagged, untagged_vid)

        return yaml.dump(config, default_flow_style=False)

    def matching_flow_present(self, exp_flow, timeout=10):
        """Find the first DP that has a flow that matches exp_flow."""

        for dpid in self.dpids:
            if self.matching_flow_present_on_dpid(dpid, exp_flow, timeout):
                return True
        return False

    def eventually_all_reachable(self, retries=3):
        """Allow time for distributed learning to happen."""
        for _ in range(retries):
            loss = self.net.pingAll()
            if loss == 0:
                break
        self.assertEquals(0, loss)


class FaucetStringOfDPUntaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3

    def setUp(self):
        super(FaucetStringOfDPUntaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS, untagged_vid=self.VID)
        self.start_net()

    def test_untagged(self):
        """All untagged hosts in multi switch topology can reach one another."""
        self.assertEquals(0, self.net.pingAll())


class FaucetStringOfDPTaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3

    def setUp(self):
        super(FaucetStringOfDPTaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, tagged_vid=self.VID)
        self.start_net()

    def test_tagged(self):
        """All tagged hosts in multi switch topology can reach one another."""
        self.assertEquals(0, self.net.pingAll())


class FaucetStackStringOfDPTaggedTest(FaucetStringOfDPTest):
    """Test topology of stacked datapaths with tagged hosts."""

    NUM_DPS = 3

    def setUp(self):
        super(FaucetStackStringOfDPTaggedTest, self).setUp()
        self.build_net(
            stack=True,
            n_dps=self.NUM_DPS,
            n_tagged=self.NUM_HOSTS,
            tagged_vid=self.VID)
        self.start_net()

    def test_tagged(self):
        """All tagged hosts in stack topology can reach each other."""
        self.eventually_all_reachable()


class FaucetStackStringOfDPUntaggedTest(FaucetStringOfDPTest):
    """Test topology of stacked datapaths with tagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 2

    def setUp(self):
        super(FaucetStackStringOfDPUntaggedTest, self).setUp()
        self.build_net(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            untagged_vid=self.VID)
        self.start_net()

    def test_untagged(self):
        """All untagged hosts in stack topology can reach each other."""
        self.eventually_all_reachable()


class FaucetSingleStringOfDPACLOverrideTest(FaucetStringOfDPTest):

    NUM_DPS = 1
    NUM_HOSTS = 2

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
        super(FaucetSingleStringOfDPACLOverrideTest, self).setUp()
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
        """Test that TCP port 5001 is blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(5001, first_host, second_host)
        open(self.acls_config, 'w').write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.hup_faucet()
        time.sleep(1)
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        """Test that TCP port 5002 is not blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        open(self.acls_config, 'w').write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.hup_faucet()
        time.sleep(1)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


def import_config():
    """Import configuration for physical switch testing."""
    try:
        with open(HW_SWITCH_CONFIG_FILE, 'r') as config_file:
            config = yaml.load(config_file)
    except:
        print 'Could not load YAML config data from %s' % HW_SWITCH_CONFIG_FILE
        sys.exit(-1)
    if 'hw_switch' in config and config['hw_switch']:
        required_config = ('dp_ports', 'dpid', 'of_port', 'gauge_of_port')
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
        return config
    else:
        return None


def check_dependencies():
    """Verify dependant libraries/binaries are present with correct versions."""
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
    """Run pylint on required source files."""
    for faucet_src in FAUCET_LINT_SRCS:
        ret = subprocess.call(['pylint', '-E', faucet_src])
        if ret:
            print 'lint of %s returns an error' % faucet_src
            return False
    return True


def make_suite(tc_class, config):
    """Compose test suite based on test class names."""
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(name, config))
    return suite


def run_tests(requested_test_classes, serial, config):
    """Actually run the test suites, potentially in parallel."""
    ports_server = threading.Thread(target=faucet_mininet_test_util.serve_ports)
    ports_server.setDaemon(True)
    ports_server.start()
    single_tests = unittest.TestSuite()
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if not inspect.isclass(obj):
            continue
        if requested_test_classes and name not in requested_test_classes:
            continue
        if name.endswith('Test') and name.startswith('Faucet'):
            print 'adding test %s' % name
            test_suite = make_suite(obj, config)
            if serial or name.startswith('FaucetSingle'):
                single_tests.addTest(test_suite)
            else:
                parallel_tests.addTest(test_suite)
    print 'running %u tests in parallel and %u tests serial' % (
        parallel_tests.countTestCases(), single_tests.countTestCases())
    results = []
    if parallel_tests.countTestCases():
        max_parallel_tests = min(parallel_tests.countTestCases(), MAX_PARALLEL_TESTS)
        parallel_runner = unittest.TextTestRunner(verbosity=255)
        parallel_suite = ConcurrentTestSuite(
            parallel_tests, fork_for_tests(max_parallel_tests))
        results.append(parallel_runner.run(parallel_suite))
    # TODO: Tests that are serialized generally depend on hardcoded ports.
    # Make them use dynamic ports.
    if single_tests.countTestCases():
        single_runner = unittest.TextTestRunner(verbosity=255)
        results.append(single_runner.run(single_tests))
    for result in results:
        if not result.wasSuccessful():
            print result.printErrors()


def parse_args():
    """Parse command line arguments."""
    try:
        opts, args = getopt.getopt(sys.argv[1:], "cs", ["clean", "serial"])
    except getopt.GetoptError as err:
        print str(err)
        sys.exit(2)

    clean = False
    serial = False

    for opt, _ in opts:
        if opt in ('-c', '--clean'):
            clean = True
        if opt in ('-s', '--serial'):
            serial = True

    return (args, clean, serial)


def test_main():
    """Test main."""
    setLogLevel('info')
    args, clean, serial = parse_args()

    if clean:
        print ('Cleaning up test interfaces, processes and openvswitch '
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
    config = import_config()
    if config is not None:
        print 'Testing hardware, forcing test serialization'
        serial = True
    run_tests(args, serial, config)


if __name__ == '__main__':
    test_main()
