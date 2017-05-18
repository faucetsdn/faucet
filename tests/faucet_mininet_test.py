#!/usr/bin/env python

"""Mininet tests for FAUCET.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest

 REQUIRES:

 * mininet 2.2.2 or later (Ubuntu 14 ships with 2.1.0, which is not supported)
   use the "install from source" option from
   https://github.com/mininet/mininet/blob/master/INSTALL.
   suggest ./util/install.sh -n
 * OVS 2.7 or later (Ubuntu 14 ships with 2.0.2, which is not supported)
 * VLAN utils (vconfig, et al - on Ubuntu, apt-get install vlan)
 * fuser
 * net-tools
 * iputils-ping
 * netcat-openbsd
 * tcpdump
 * exabgp
 * pylint
 * curl
 * ladvd
 * iperf
"""

import collections
import glob
import inspect
import os
import sys
import getopt
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer

import ipaddress
import yaml

from concurrencytest import ConcurrentTestSuite, fork_for_tests
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Intf
from mininet.util import dumpNodeConnections, pmonitor
from mininet.clean import Cleanup
from packaging import version

import faucet_mininet_test_util
import faucet_mininet_test_base


# list of required external dependencies
# external binary, argument to get version,
# RE to check present RE to get version, minimum required version.
EXTERNAL_DEPENDENCIES = (
    ('ryu-manager', ['--version'],
     'ryu-manager', r'ryu-manager (\d+\.\d+)\n', "4.9"),
    ('ovs-vsctl', ['--version'], 'Open vSwitch',
     r'ovs-vsctl\s+\(Open vSwitch\)\s+(\d+\.\d+)\.\d+\n', "2.3"),
    ('tcpdump', ['-h'], 'tcpdump',
     r'tcpdump\s+version\s+(\d+\.\d+)\.\d+\n', "4.5"),
    ('nc', [], 'nc from the netcat-openbsd', '', 0),
    ('vconfig', [], 'the VLAN you are talking about', '', 0),
    ('2to3', ['--help'], 'Usage: 2to3', '', 0),
    ('fuser', ['-V'], r'fuser \(PSmisc\)',
     r'fuser \(PSmisc\) (\d+\.\d+)\n', "22.0"),
    ('mn', ['--version'], r'\d+\.\d+.\d+',
     r'(\d+\.\d+).\d+', "2.2"),
    ('exabgp', ['--version'], 'ExaBGP',
     r'ExaBGP : (\d+\.\d+).\d+', "3.4"),
    ('pip', ['show', 'influxdb'], 'influxdb',
     r'Version:\s+(\d+\.\d+)\.\d+', "3.0"),
    ('pylint', ['--version'], 'pylint',
     r'pylint (\d+\.\d+).\d+,', "1.6"),
    ('curl', ['--version'], 'libcurl',
     r'curl (\d+\.\d+).\d+', "7.3"),
    ('ladvd', ['-h'], 'ladvd',
     r'ladvd version (\d+\.\d+)\.\d+', "1.1"),
    ('iperf', ['--version'], 'iperf',
     r'iperf version (\d+\.\d+)\.\d+', "2.0"),
)

# Must pass with 0 lint errors
FAUCET_LINT_SRCS = glob.glob(
    os.path.join(faucet_mininet_test_util.FAUCET_DIR, '*py'))
FAUCET_TEST_LINT_SRCS = [
    os.path.join(os.path.dirname(__file__), 'faucet_mininet_test.py'),
    os.path.join(os.path.dirname(__file__), 'faucet_mininet_test_base.py')]

# Maximum number of parallel tests to run at once
MAX_PARALLEL_TESTS = 4

# see hw_switch_config.yaml for how to bridge in an external hardware switch.
HW_SWITCH_CONFIG_FILE = 'hw_switch_config.yaml'
CONFIG_FILE_DIRS = ['/etc/ryu/faucet', './']
REQUIRED_TEST_PORTS = 4


class FaucetTest(faucet_mininet_test_base.FaucetTestBase):

    RUN_GAUGE = True

    def setUp(self):
        self.tmpdir = self.tmpdir_name()
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
        prom_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        os.environ['FAUCET_PROMETHEUS_PORT'] = str(prom_port)
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
                self.cpn_intf = self.config['cpn_intf']
                self.of_port = self.config['of_port']
                self.gauge_of_port = self.config['gauge_of_port']
                self.hardware = self.config['hardware']
                if 'ctl_privkey' in self.config:
                    self.ctl_privkey = self.config['ctl_privkey']
                if 'ctl_cert' in self.config:
                    self.ctl_cert = self.config['ctl_cert']
                if 'ca_certs' in self.config:
                    self.ca_certs = self.config['ca_certs']
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
            self.of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)
            self.gauge_of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)

        self.CONFIG = '\n'.join((
            self.get_config_header(
                self.CONFIG_GLOBAL, self.debug_log_path, self.dpid, self.hardware),
            self.CONFIG % self.port_map))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.influx_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        self.GAUGE_CONFIG = self.get_gauge_config(
            os.environ['FAUCET_CONFIG'],
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file,
            self.influx_port,
            )
        open(os.environ['GAUGE_CONFIG'], 'w').write(self.GAUGE_CONFIG)

        self.net = None
        self.topo = None

    def attach_physical_switch(self):
        """Bridge a physical switch into test topology."""
        switch = self.net.switches[0]
        mapped_base = max(len(self.switch_map), len(self.port_map))
        for i, test_host_port in enumerate(sorted(self.switch_map)):
            port_i = i + 1
            mapped_port_i = mapped_base + port_i
            phys_port = Intf(self.switch_map[test_host_port], node=switch)
            switch.cmd('ip link set dev %s up' % phys_port)
            switch.cmd(
                ('ovs-vsctl add-port %s %s -- '
                 'set Interface %s ofport_request=%u') % (
                     switch.name,
                     phys_port.name,
                     phys_port.name,
                     mapped_port_i))
            for port_pair in ((port_i, mapped_port_i), (mapped_port_i, port_i)):
                port_x, port_y = port_pair
                switch.cmd('%s add-flow %s in_port=%u,actions=output:%u' % (
                    self.OFCTL, switch.name, port_x, port_y))

    def start_net(self):
        """Start Mininet network."""
        controller_intf = 'lo'
        if self.hw_switch:
            controller_intf = self.cpn_intf
        self.net = Mininet(
            self.topo,
            controller=faucet_mininet_test_base.FAUCET(
                name='faucet', tmpdir=self.tmpdir,
                controller_intf=controller_intf,
                ctl_privkey=self.ctl_privkey,
                ctl_cert=self.ctl_cert,
                ca_certs=self.ca_certs,
                ports_sock=self.ports_sock,
                port=self.of_port))
        self.pre_start_net()
        if self.RUN_GAUGE:
            gauge_controller = faucet_mininet_test_base.Gauge(
                name='gauge', tmpdir=self.tmpdir,
                controller_intf=controller_intf,
                ctl_privkey=self.ctl_privkey,
                ctl_cert=self.ctl_cert,
                ca_certs=self.ca_certs,
                port=self.gauge_of_port)
            self.net.addController(gauge_controller)
        self.net.start()
        if self.hw_switch:
            self.attach_physical_switch()
        self.wait_debug_log()
        self.wait_until_matching_flow('OUTPUT:CONTROLLER')
        dumpNodeConnections(self.net.hosts)

    def tcpdump_helper(self, tcpdump_host, tcpdump_filter, funcs=[],
                       timeout=10, packets=2, root_intf=False):
        intf = tcpdump_host.intf().name
        if root_intf:
            intf = intf.split('.')[0]
        tcpdump_cmd = self.timeout_soft_cmd(
            'tcpdump -i %s -e -n -U -v -c %u %s' % (
                intf, packets, tcpdump_filter),
            timeout)
        tcpdump_out = tcpdump_host.popen(tcpdump_cmd, stderr=subprocess.STDOUT)
        popens = {tcpdump_host: tcpdump_out}
        tcpdump_started = False
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == tcpdump_host:
                if tcpdump_started:
                    tcpdump_txt += line.strip()
                elif re.search('tcpdump: listening on ', line):
                    # when we see tcpdump start, then call provided functions.
                    tcpdump_started = True
                    for func in funcs:
                        func()
                else:
                    print('tcpdump_helper: %s' % line)
        self.assertTrue(tcpdump_started)
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

    def verify_lldp_blocked(self):
        first_host, second_host = self.net.hosts[0:2]
        lldp_filter = 'ether proto 0x88cc'
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        send_lldp = '%s -L -o %s' % (
            self.timeout_cmd(self.LADVD, 30),
            second_host.defaultIntf())
        tcpdump_txt = self.tcpdump_helper(
            first_host, lldp_filter,
            [lambda: second_host.cmd(ladvd_mkdir),
             lambda: second_host.cmd(send_lldp),
             lambda: second_host.cmd(send_lldp),
             lambda: second_host.cmd(send_lldp)],
            timeout=20, packets=5)
        if re.search(second_host.MAC(), tcpdump_txt):
            return False
        return True

    def is_cdp_blocked(self):
        first_host, second_host = self.net.hosts[0:2]
        cdp_filter = 'ether host 01:00:0c:cc:cc:cc and ether[20:2]==0x2000'
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        send_cdp = '%s -C -o %s' % (
            self.timeout_cmd(self.LADVD, 30),
            second_host.defaultIntf())
        tcpdump_txt = self.tcpdump_helper(
            first_host,
            cdp_filter,
            [lambda: second_host.cmd(ladvd_mkdir),
             lambda: second_host.cmd(send_cdp),
             lambda: second_host.cmd(send_cdp),
             lambda: second_host.cmd(send_cdp)],
            timeout=20, packets=5)

        if re.search(second_host.MAC(), tcpdump_txt):
            return False
        return True

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

    def verify_eapol_mirrored(self, first_host, second_host, mirror_host):
        self.net.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.assertEquals(0, self.net.ping((first_host, second_host)))
        mirror_mac = mirror_host.MAC()
        tmp_eap_conf = os.path.join(self.tmpdir, 'eap.conf')
        tcpdump_filter = (
            'not ether src %s and ether proto 0x888e' % mirror_mac)
        eap_conf_cmd = (
            'echo "eapol_version=2\nap_scan=0\nnetwork={\n'
            'key_mgmt=IEEE8021X\neap=MD5\nidentity=\\"login\\"\n'
            'password=\\"password\\"\n}\n" > %s' % tmp_eap_conf)
        wpa_supplicant_cmd = self.timeout_cmd(
            'wpa_supplicant -c%s -Dwired -i%s -d' % (
                tmp_eap_conf,
                first_host.defaultIntf().name),
            5)
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd(eap_conf_cmd),
                lambda: first_host.cmd(wpa_supplicant_cmd)])
        self.assertTrue(
            re.search('01:80:c2:00:00:03, ethertype EAPOL', tcpdump_txt),
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
            if (os.path.exists(watcher_file) and
                    os.stat(watcher_file).st_size > 0):
                continue
            self.fail(
                'gauge did not output %s (gauge not connected?)' % watcher_file)
        self.verify_no_exception('FAUCET_EXCEPTION_LOG')
        self.verify_no_exception('GAUGE_EXCEPTION_LOG')

    def prometheus_smoke_test(self):
        prom_out = self.scrape_prometheus()
        self.assertTrue(re.search(r'of_packet_ins\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'of_flowmsgs_sent\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'of_dp_connections\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'faucet_config\S+name=\"flood\"\S+', prom_out), msg=prom_out)
        self.assertIsNone(re.search(r'of_errors', prom_out), msg=prom_out)
        self.assertIsNone(re.search(r'of_dp_disconnections', prom_out), msg=prom_out)


class FaucetAPITest(faucet_mininet_test_base.FaucetTestBase):
    """Test the Faucet API."""

    def setUp(self):
        self.tmpdir = self.tmpdir_name()
        self.results_file = os.path.join(
            self.tmpdir, 'result.txt')
        os.environ['API_TEST_RESULT'] = self.results_file
        shutil.copytree('config', os.path.join(self.tmpdir, 'config'))
        os.environ['FAUCET_CONFIG'] = os.path.join(
            self.tmpdir, 'config/testconfigv2-simple.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(
            self.tmpdir, 'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(
            self.tmpdir, 'faucet-exception.log')
        self.dpid = str(0xcafef00d)
        self.of_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        self.topo = faucet_mininet_test_base.FaucetSwitchTopo(
            self.ports_sock,
            dpid=self.dpid,
            n_untagged=7
            )
        self.net = Mininet(
            self.topo,
            controller=faucet_mininet_test_base.FaucetAPI(
                name='faucet-api',
                port=self.of_port
                )
            )
        self.net.start()

    def test_api(self):
        countdown = 30
        while countdown > 0:
            try:
                with open(self.results_file, 'r') as results:
                    result = results.read().strip()
                    self.assertEquals('pass', result, result)
                    return
            except IOError:
                countdown -= 1
                time.sleep(1)
        self.fail('no result from API test')


class FaucetUntaggedTest(FaucetTest):
    """Basic untagged VLAN test."""

    N_UNTAGGED = 4
    N_TAGGED = 0
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
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid,
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED)
        self.start_net()

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.gauge_smoke_test()
        self.prometheus_smoke_test()


class FaucetUntaggedTcpIperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        for _ in range(3):
            self.ping_all_when_learned()
            first_host, second_host = self.net.hosts[:2]
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                'TCP', 1)
            self.flap_all_switch_ports()


class FaucetSanityTest(FaucetUntaggedTest):
    """Sanity test - make sure test environment is correct before running all tess."""

    pass


class FaucetUntaggedInfluxTest(FaucetUntaggedTest):
    """Basic untagged VLAN test with Influx."""

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['faucet-1']
        type: 'port_stats'
        interval: 2
        db: 'influx'
    port_state:
        dps: ['faucet-1']
        type: 'port_state'
        interval: 2
        db: 'influx'
"""

    def test_untagged_influx_down(self):
        self.ping_all_when_learned()
        self.verify_no_exception('FAUCET_EXCEPTION_LOG')

    def test_untagged(self):

        class PostHandler(SimpleHTTPRequestHandler):

            def do_POST(self):
                content_len = int(self.headers.getheader('content-length', 0))
                content = self.rfile.read(content_len)
                open(os.environ['INFLUXLOG'], 'a').write(content)
                return self.send_response(204)

        os.environ['INFLUXLOG'] = os.path.join(self.tmpdir, 'influx.log')
        server = HTTPServer(('', self.influx_port), PostHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        self.ping_all_when_learned()
        for _ in range(3):
            if os.path.exists(os.environ['INFLUXLOG']):
                break
            time.sleep(2)
        server.shutdown()
        self.assertTrue(os.path.exists(os.environ['INFLUXLOG']))


class FaucetNailedForwardingTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    port: b1
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
                output:
                    port: b2
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    port: b1
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    port: b2
        - rule:
            actions:
                allow: 0
"""

    CONFIG = """
        interfaces:
            b1:
                number: %(port_1)d
                native_vlan: 100
                acl_in: 1
            b2:
                number: %(port_2)d
                native_vlan: 100
                acl_in: 1
            b3:
                number: %(port_3)d
                native_vlan: 100
                acl_in: 1
            b4:
                number: %(port_4)d
                native_vlan: 100
                acl_in: 1
"""

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        first_host.setMAC("0e:00:00:00:01:01")
        second_host.setMAC("0e:00:00:00:02:02")
        self.one_ipv4_ping(
            first_host, second_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            second_host, first_host.IP(), require_host_learned=False)



class FaucetUntaggedLLDPBlockedTest(FaucetUntaggedTest):

    def test_untagged(self):
        self.ping_all_when_learned()
        self.assertTrue(self.verify_lldp_blocked())


class FaucetUntaggedCDPTest(FaucetUntaggedTest):

    def test_untagged(self):
        self.ping_all_when_learned()
        self.assertFalse(self.is_cdp_blocked())


class FaucetUntaggedLLDPUnblockedTest(FaucetUntaggedTest):

    CONFIG = """
        drop_lldp: False
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
        self.ping_all_when_learned()
        self.assertFalse(self.verify_lldp_blocked())


class FaucetZodiacUntaggedTest(FaucetUntaggedTest):
    """Zodiac has only 3 ports available, and one controller so no Gauge."""

    RUN_GAUGE = False
    N_UNTAGGED = 3

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


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
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid, n_tagged=1, n_untagged=3)
        self.start_net()

    def test_untagged(self):
        """Test connectivity including after port flapping."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


class FaucetZodiacTaggedAndUntaggedVlanTest(FaucetUntaggedTest):

    RUN_GAUGE = False
    N_TAGGED = 1
    N_UNTAGGED = 2
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
        self.net.pingAll()
        learned_hosts = [
            host for host in self.net.hosts if self.host_learned(host)]
        self.assertEquals(2, len(learned_hosts))
        self.assertEquals(2, int(self.scrape_prometheus_var(
            r'vlan_hosts_learned\S+vlan="100"\S+')))


class FaucetMaxHostsPortTest(FaucetUntaggedTest):

    MAX_HOSTS = 3
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
                max_hosts: 3
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.ping_all_when_learned()
        for i in range(10, 10+(self.MAX_HOSTS*2)):
            mac_intf = 'mac%u' % i
            mac_ipv4 = '10.0.0.%u' % i
            second_host.cmd('ip link add link %s %s type macvlan' % (
                second_host.defaultIntf(), mac_intf))
            second_host.cmd('ip address add %s/24 dev %s' % (
                mac_ipv4, mac_intf))
            second_host.cmd('ip link set dev %s up' % mac_intf)
            second_host.cmd('ping -c1 -I%s %s &' % (mac_intf, first_host.IP()))

        flows = self.get_all_flows_from_dpid(self.dpid)
        exp_flow = (
            '"table_id": 3, "match": '
            '{"dl_vlan": "100", "dl_src": "..:..:..:..:..:..", '
            '"in_port": %u' % self.port_map['port_2'])
        macs_learned = 0
        for flow in flows:
            if re.search(exp_flow, flow):
                macs_learned += 1
        self.assertEquals(self.MAX_HOSTS, macs_learned)
        prom_txt = self.scrape_prometheus()
        self.assertEquals(self.MAX_HOSTS,
            len(re.findall(r'learned_macs\S+port="2"\Svlan="100"\S+', prom_txt)))


class FaucetHostsTimeoutPrometheusTest(FaucetUntaggedTest):
    '''Test for hosts that have been learnt are exported via prometheus.
       Hosts should timeout, and the exported prometheus values should
       be overwritten.
       If the maximum number of MACs at any one time is 5, then only 5 values
       should be exported, even if over 2 hours, there are 100 MACs learnt
    '''
    TIMEOUT = 30
    MAX_HOSTS = 50
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        timeout: 30
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

    def mac_as_int(self, mac):
        return int(mac.replace(':',''), 16)

    def are_hosts_learnt(self, hosts):

        flows = self.get_all_flows_from_dpid(self.dpid)
        prom_txt = self.scrape_prometheus()
        macs_learned = 0
        for mac, port in hosts.items():
            exp_flow = (
                '"table_id": 3, "match": '
                '{"dl_vlan": "100", "dl_src": "%s", '
                '"in_port": %u' % (mac, port))
            prog = re.compile(exp_flow)
            for flow in flows:
                if prog.search(flow):
                    macs_learned += 1
                    break
            self.assertTrue(
                re.search(r'learned_macs\S+port="%u"\Svlan="100"}\s%u.0'
                     % (port, self.mac_as_int(mac)), prom_txt),
                msg='port: {}, mac: {}, mac_int: {}'.format(port, mac, self.mac_as_int(mac)))
        self.assertEquals(len(hosts), macs_learned)

    def check_prometheus_overwrite(self, port, num_empty, num_valid):
        '''Checks that prometheus has zeroed out expired mac learning entries.
        '''
        prom_txt = self.scrape_prometheus() 
        learned_macs = re.findall(r'learned_macs\S+port="%u"\Svlan="100"}\s\d+.0' % port, prom_txt)

        count_empty = 0
        count_valid = 0
        for l in learned_macs:
            print(l.split(' ')[1])
            if l.split(' ')[1] == '0.0':
                count_empty += 1
            else:
                count_valid += 1

        self.assertEqual(count_empty, num_empty)
        self.assertEqual(count_valid, num_valid)
    
    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        learned_mac_ports = {}
        learned_mac_ports[first_host.MAC()] = self.port_map['port_1']
        mac_intfs = []
        for i in range(10, 16):
            if i == 14:
                for mac_intf in mac_intfs:
                    self.one_ipv4_ping(
                        second_host, first_host.IP(),
                        require_host_learned=True, intf=mac_intf)
                # check first 4 are learnt
                self.are_hosts_learnt(learned_mac_ports)
                learned_mac_ports = {}
                mac_intfs = []
                # wait for first lot to time out. 
                # Adding 11 covers the random variation when a rule is added
                time.sleep(self.TIMEOUT + 11)

            mac_intf = 'mac%u' % i
            mac_intfs.append(mac_intf)
            mac_ipv4 = '10.0.0.%u' % i
            second_host.cmd('ip link add link %s %s type macvlan' % (
                second_host.defaultIntf(), mac_intf))
            second_host.cmd('ip address add %s/24 dev %s' % (
                mac_ipv4, mac_intf))
            address = second_host.cmd('ip link show %s | grep -o "..:..:..:..:..:.." | head -1 | xargs echo -n' % mac_intf)
            learned_mac_ports[address] = self.port_map['port_2']
            second_host.cmd('ip link set dev %s up' % mac_intf)
            second_host.cmd('ping -c1 -I%s %s' % (mac_intf, first_host.IP()))
        for mac_intf in mac_intfs:
            self.one_ipv4_ping(
                second_host, first_host.IP(),
                require_host_learned=False, intf=mac_intf)

        learned_mac_ports[first_host.MAC()] = self.port_map['port_1']
        self.are_hosts_learnt(learned_mac_ports)
        self.check_prometheus_overwrite(2, 2, len(learned_mac_ports))


class FaucetLearn50MACsOnPortTest(FaucetUntaggedTest):

    MAX_HOSTS = 50
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

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.ping_all_when_learned()
        mac_intf_ipv4s = []
        for i in range(10, 10+self.MAX_HOSTS):
            mac_intf_ipv4s.append(('mac%u' % i, '10.0.0.%u' % i))
        # configure macvlan interfaces and stimulate learning
        for mac_intf, mac_ipv4 in mac_intf_ipv4s:
            second_host.cmd('ip link add link %s %s type macvlan' % (
                second_host.defaultIntf(), mac_intf))
            second_host.cmd('ip address add %s/24 dev %s' % (
                mac_ipv4, mac_intf))
            second_host.cmd('ip link set dev %s up' % mac_intf)
            second_host.cmd('ping -c1 -I%s %s &' % (mac_intf, first_host.IP()))
        # verify connectivity
        for mac_intf, _ in mac_intf_ipv4s:
            self.one_ipv4_ping(
                second_host, first_host.IP(),
                require_host_learned=False, intf=mac_intf)
        # verify FAUCET thinks it learned this many hosts
        self.assertGreater(int(self.scrape_prometheus_var(
            r'vlan_hosts_learned\S+vlan="100"\S+')), self.MAX_HOSTS)


class FaucetUntaggedHUPTest(FaucetUntaggedTest):
    """Test handling HUP signal without config change."""

    def test_untagged(self):
        """Test that FAUCET receives HUP signal and keeps switching."""
        switch = self.net.switches[0]
        for i in range(0, 3):
            configure_count = self.get_configure_count()
            self.assertEquals(i, int(configure_count))
            self.verify_hup_faucet()
            configure_count = self.get_configure_count()
            self.assertTrue(i + 1, configure_count)
            self.assertEqual(
                int(self.scrape_prometheus_var(
                    r'of_dp_disconnections{dpid="0x%x"}' % long(self.dpid), 0)),
                0)
            self.assertEqual(
                int(self.scrape_prometheus_var(
                    r'of_dp_connections{dpid="0x%x"}' % long(self.dpid), 0)),
                1)
            self.wait_until_matching_flow('OUTPUT:CONTROLLER')
            self.ping_all_when_learned()


class FaucetConfigReloadTest(FaucetTest):
    """Test handling HUP signal with config change."""

    N_UNTAGGED = 4
    N_TAGGED = 0
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
    ACL = """
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
    2:
        - rule:
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 5001
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            nw_proto: 6
            tp_dst: 5002
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
"""
    def setUp(self):
        super(FaucetConfigReloadTest, self).setUp()
        self.acl_config_file = '%s/acl.yaml' % self.tmpdir
        open(self.acl_config_file, 'w').write(self.ACL)
        open(os.environ['FAUCET_CONFIG'], 'a').write(
            'include:\n     - %s' % self.acl_config_file)
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid,
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED)
        self.start_net()

    def get_port_match_flow(self, port_no, table_id=3):
        exp_flow = '"table_id: %d".+"in_port": %s' % (table_id, port_no)
        flow = self.get_matching_flow_on_dpid(self.dpid, exp_flow)
        return flow

    def change_port_config(self, port, config_name, config_value, restart=True):
        conf = yaml.load(open(os.environ['FAUCET_CONFIG'], 'r').read())
        conf['dps']['faucet-1']['interfaces'][port][config_name] = config_value
        open(os.environ['FAUCET_CONFIG'], 'w').write(yaml.dump(conf))
        if restart:
            self.verify_hup_faucet()

    def change_vlan_config(self, vlan, config_name, config_value, restart=True):
        conf = yaml.load(open(os.environ['FAUCET_CONFIG'], 'r').read())
        conf['vlans'][vlan][config_name] = config_value
        open(os.environ['FAUCET_CONFIG'], 'w').write(yaml.dump(conf))
        if restart:
            self.verify_hup_faucet()

    def test_port_change_vlan(self):
        first_host = self.net.hosts[0]
        second_host = self.net.hosts[1]
        self.ping_all_when_learned()
        self.change_port_config(1, 'native_vlan', 200, restart=False)
        self.change_port_config(2, 'native_vlan', 200, restart=True)
        self.wait_until_matching_flow(
            r'SET_FIELD: {vlan_vid:4296}.+in_port": 1',
            timeout=2)
        self.one_ipv4_ping(first_host, second_host.IP(), require_host_learned=False)

    def test_port_change_acl(self):
        self.ping_all_when_learned()
        self.change_port_config(1, 'acl_in', 1)
        self.wait_until_matching_flow(
            r'"actions": \[\].+"in_port": 1, "tp_dst": 5001')
        first_host, second_host = self.net.hosts[0:2]
        self.ping_all_when_learned()
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)

    def test_port_change_permanent_learn(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.change_port_config(1, 'permanent_learn', True)
        self.ping_all_when_learned()
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned()
        self.change_port_config(1, 'acl_in', 1)
        self.wait_until_matching_flow(
            r'"actions": \[\].+"in_port": 1, "tp_dst": 5001')
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetSingleUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_neighbor_as: 2
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
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
      route 10.0.4.0/24 next-hop 10.0.0.254;
      route 10.0.5.0/24 next-hop 10.10.0.1;
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
            first_host.MAC(), ipaddress.IPv4Network(u'10.99.99.0/24'))
        self.wait_bgp_up('127.0.0.1', 100)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route('10.0.0.4/24 cannot be us')
        self.verify_invalid_bgp_route('10.0.0.5/24 is not a connected network')
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv4Network(u'10.0.3.0/24'))
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
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
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
        max_resolve_backoff_time: 1
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
        self.wait_bgp_up('127.0.0.1', 100)
        # exabgp should have received our BGP updates
        updates = self.exabgp_updates(self.exabgp_log)
        self.stop_exabgp()
        assert re.search('10.0.0.0/24 next-hop 10.0.0.254', updates)
        assert re.search('10.0.1.0/24 next-hop 10.0.0.1', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)


class FaucetSingleZodiacUntaggedIPv4RouteTest(FaucetSingleUntaggedIPv4RouteTest):

    RUN_GAUGE = False
    N_UNTAGGED = 3


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
        # Unicast flooding rule for from port 1
        self.assertTrue(self.matching_flow_present(
            '"table_id": 7, "match": {"dl_vlan": "100", "in_port": %(port_1)d}' % self.port_map))
        # Unicast flood rule exists that output to port 1
        self.assertTrue(self.matching_flow_present(
            '"OUTPUT:%(port_1)d".+"table_id": 7, "match": {"dl_vlan": "100", "in_port": .+}' % self.port_map))
        self.assertTrue(self.bogus_mac_flooded_to_port1())


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
        # No unicast flooding rule for from port 1
        self.assertFalse(self.matching_flow_present(
            '"table_id": 7, "match": {"dl_vlan": "100", "in_port": %(port_1)d}' % self.port_map))
        # No unicast flood rule exists that output to port 1
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:%(port_1)d".+"table_id": 7, "match": {"dl_vlan": "100", "in_port": .+}' % self.port_map))
        self.assertFalse(self.bogus_mac_flooded_to_port1())


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
        # No unicast flooding rule for from port 1
        self.assertFalse(self.matching_flow_present(
            '"table_id": 7, "match": {"dl_vlan": "100", "in_port": %(port_1)d}' % self.port_map))
        # No unicast flood rule exists that output to port 1
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:%(port_1)d".+"table_id": 7, "match": {"dl_vlan": "100", "in_port": .+}' % self.port_map))
        # VLAN level config to disable flooding takes precedence,
        # cannot enable port-only flooding.
        self.assertFalse(self.bogus_mac_flooded_to_port1())


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
        # Unicast flood rule present for port 2, but NOT for port 1
        self.assertTrue(self.matching_flow_present(
            '"table_id": 7, "match": {"dl_vlan": "100", "in_port": %(port_2)d}' % self.port_map))
        self.assertFalse(self.matching_flow_present(
            '"table_id": 7, "match": {"dl_vlan": "100", "in_port": %(port_1)d}' % self.port_map))
        # Unicast flood rules present that output to port 2, but NOT to port 1
        self.assertTrue(self.matching_flow_present(
            '"OUTPUT:%(port_2)d".+"table_id": 7, "match": {"dl_vlan": "100", "in_port": .+}' % self.port_map))
        self.assertFalse(self.matching_flow_present(
            '"OUTPUT:%(port_1)d".+"table_id": 7, "match": {"dl_vlan": "100", "in_port": .+}' % self.port_map))
        self.assertFalse(self.bogus_mac_flooded_to_port1())


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


class FaucetUntaggedIPv4ControlPlaneTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
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
        for _ in range(5):
            self.one_ipv4_ping(first_host, second_host.IP())
            for host in first_host, second_host:
                self.one_ipv4_controller_ping(host)
            self.flap_all_switch_ports()


class FaucetUntaggedIPv6ControlPlaneTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
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
        for _ in range(5):
            self.one_ipv6_ping(first_host, 'fc00::1:2')
            for host in first_host, second_host:
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
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid, n_tagged=2, n_untagged=2)
        self.start_net()

    def test_seperate_untagged_tagged(self):
        tagged_host_pair = self.net.hosts[:2]
        untagged_host_pair = self.net.hosts[2:]
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


class FaucetZodiacUntaggedACLTest(FaucetUntaggedACLTest):

    RUN_GAUGE = False
    N_UNTAGGED = 3

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


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

    def test_eapol_mirrored(self):
        first_host, second_host, mirror_host = self.net.hosts[0:3]
        self.verify_eapol_mirrored(first_host, second_host, mirror_host)


class FaucetZodiacUntaggedACLMirrorTest(FaucetUntaggedACLMirrorTest):

    RUN_GAUGE = False
    N_UNTAGGED = 3


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


class FaucetUntaggedMultiVlansOutputTest(FaucetUntaggedTest):

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
                    vlan_vids: [123, 456]
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

    @unittest.skip('needs OVS dev or > v2.8')
    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = 'vlan'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 456.+vlan 123', tcpdump_txt))


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
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid, n_tagged=4)
        self.start_net()

    def test_tagged(self):
        self.ping_all_when_learned()


class FaucetTaggedPopVlansOutputTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        unicast_flood: False
acls:
    1:
        - rule:
            vlan_vid: 100
            dl_dst: "01:02:03:04:05:06"
            actions:
                output:
                    dl_dst: "06:06:06:06:06:06"
                    pop_vlans: 1
                    port: acloutport
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                description: "b1"
                acl_in: 1
            acloutport:
                tagged_vlans: [100]
                number: %(port_2)d
                description: "b2"
            %(port_3)d:
                tagged_vlans: [100]
                description: "b3"
            %(port_4)d:
                tagged_vlans: [100]
                description: "b4"
"""

    def test_tagged(self):
        first_host, second_host = self.net.hosts[0:2]
        tcpdump_filter = 'not vlan and icmp and ether dst 06:06:06:06:06:06'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())], packets=10, root_intf=True)
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))


class FaucetTaggedIPv4ControlPlaneTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
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
        self.one_ipv4_ping(first_host, second_host.IP())
        for host in first_host, second_host:
            self.one_ipv4_controller_ping(host)


class FaucetTaggedIPv6ControlPlaneTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["fc00::1:254/112"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
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
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        for host in first_host, second_host:
            self.one_ipv6_controller_ping(host)


class FaucetTaggedIPv4RouteTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["10.0.0.254/24"]
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
        max_resolve_backoff_time: 1
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
        first_host_routed_ip = ipaddress.ip_interface(u'10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface(u'10.0.2.1/24')
        for _ in range(3):
            self.verify_ipv4_routing(
                first_host, first_host_routed_ip,
                second_host, second_host_routed_ip)
            self.swap_host_macs(first_host, second_host)


class FaucetUntaggedIPv4InterVLANRouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "100"
        faucet_vips: ["10.100.0.254/24"]
    200:
        description: "200"
        faucet_vips: ["10.200.0.254/24"]
routers:
    router-1:
        vlans: [100, 200]
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                native_vlan: 200
                description: "b2"
            %(port_3)d:
                native_vlan: 200
                description: "b3"
            %(port_4)d:
                native_vlan: 200
                description: "b4"
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface(u'10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface(u'10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface(u'10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface(u'10.200.0.254/24')
        first_host, second_host = self.net.hosts[:2]
        first_host.setIP(str(first_host_ip.ip))
        second_host.setIP(str(second_host_ip.ip))
        self.add_host_route(first_host, second_host_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(first_host, first_faucet_vip.ip)
        self.one_ipv4_ping(second_host, second_faucet_vip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)


class FaucetUntaggedMixedIPv4RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["172.16.0.254/24", "10.0.0.254/24"]
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
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
        first_host_net = ipaddress.ip_interface(u'10.0.0.1/24')
        second_host_net = ipaddress.ip_interface(u'172.16.0.1/24')
        second_host.setIP(str(second_host_net.ip))
        self.one_ipv4_ping(first_host, self.FAUCET_VIPV4.ip)
        self.one_ipv4_ping(second_host, self.FAUCET_VIPV4_2.ip)
        self.add_host_route(
            first_host, second_host_net, self.FAUCET_VIPV4.ip)
        self.add_host_route(
            second_host, first_host_net, self.FAUCET_VIPV4_2.ip)
        self.one_ipv4_ping(first_host, second_host_net.ip)
        self.one_ipv4_ping(second_host, first_host_net.ip)


class FaucetUntaggedMixedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/64", "fc01::1:254/64"]
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
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
        first_host_net = ipaddress.ip_interface(u'fc00::1:1/64')
        second_host_net = ipaddress.ip_interface(u'fc01::1:1/64')
        self.add_host_ipv6_address(first_host, first_host_net)
        self.one_ipv6_ping(first_host, self.FAUCET_VIPV6.ip)
        self.add_host_ipv6_address(second_host, second_host_net)
        self.one_ipv6_ping(second_host, self.FAUCET_VIPV6_2.ip)
        self.add_host_route(
            first_host, second_host_net, self.FAUCET_VIPV6.ip)
        self.add_host_route(
            second_host, first_host_net, self.FAUCET_VIPV6_2.ip)
        self.one_ipv6_ping(first_host, second_host_net.ip)
        self.one_ipv6_ping(second_host, first_host_net.ip)


class FaucetSingleUntaggedBGPIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["::1"]
        bgp_neighbor_as: 2
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
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
      route fc00::40:1/112 next-hop fc00::1:254;
      route fc00::50:1/112 next-hop fc00::2:2;
    }
  }
}
"""
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf, '::1')

    def test_untagged(self):
        self.wait_bgp_up('::1', 100)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route('fc00::40:1/112 cannot be us')
        self.verify_invalid_bgp_route('fc00::50:1/112 is not a connected network')
        self.verify_ipv6_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv6_routing_mesh()
        self.stop_exabgp()


class FaucetUntaggedSameVlanIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::10:1/112", "fc00::20:1/112"]
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
        max_resolve_backoff_time: 1
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
        first_host_ip = ipaddress.ip_interface(u'fc00::10:2/112')
        first_host_ctrl_ip = ipaddress.ip_address(u'fc00::10:1')
        second_host_ip = ipaddress.ip_interface(u'fc00::20:2/112')
        second_host_ctrl_ip = ipaddress.ip_address(u'fc00::20:1')
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_route(
            first_host, second_host_ip, first_host_ctrl_ip)
        self.add_host_route(
            second_host, first_host_ip, second_host_ctrl_ip)
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_ip.network)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_ip.network)
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(first_host, second_host_ctrl_ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ctrl_ip)


class FaucetSingleUntaggedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: 9179
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["::1"]
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
        max_resolve_backoff_time: 1
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
            second_host.MAC(), ipaddress.IPv6Network(u'fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        self.wait_bgp_up('::1', 100)
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
        faucet_vips: ["fc00::1:254/112"]
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
        max_resolve_backoff_time: 1
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
        first_host_ip = ipaddress.ip_interface(u'fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface(u'fc00::1:2/112')
        first_host_routed_ip = ipaddress.ip_interface(u'fc00::10:1/112')
        second_host_routed_ip = ipaddress.ip_interface(u'fc00::20:1/112')
        for _ in range(5):
            self.verify_ipv6_routing_pair(
                first_host, first_host_ip, first_host_routed_ip,
                second_host, second_host_ip, second_host_routed_ip)
            self.swap_host_macs(first_host, second_host)


class FaucetStringOfDPSwitchTopo(faucet_mininet_test_base.FaucetSwitchTopo):

    def build(self, ports_sock, dpids, n_tagged=0, tagged_vid=100, n_untagged=0):
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
            port, ports_served = faucet_mininet_test_util.find_free_port(
                ports_sock)
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
        self.dpid = self.dpids[0]
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
        self.topo = FaucetStringOfDPSwitchTopo(
            self.ports_sock,
            dpids=self.dpids,
            n_tagged=n_tagged,
            tagged_vid=tagged_vid,
            n_untagged=n_untagged,
        )

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
        self.verify_hup_faucet()
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        """Test that TCP port 5002 is not blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        open(self.acls_config, 'w').write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.verify_hup_faucet()
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
        self.assertEqual(
            100,
            self.get_group_id_for_matching_flow(
                '"table_id": 7,.+"dl_dst".+"dl_vlan": "100"'))


class FaucetSingleGroupTableUntaggedIPv4RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
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
        max_resolve_backoff_time: 1
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
        first_host_routed_ip = ipaddress.ip_interface(u'10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface(u'10.0.2.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=True)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=True)


class FaucetSingleGroupUntaggedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
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
        max_resolve_backoff_time: 1
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
        first_host_ip = ipaddress.ip_interface(u'fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface(u'fc00::1:2/112')
        first_host_routed_ip = ipaddress.ip_interface(u'fc00::10:1/112')
        second_host_routed_ip = ipaddress.ip_interface(u'fc00::20:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=True)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=True)


class FaucetDestRewriteTest(FaucetUntaggedTest):
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            dl_dst: "00:00:00:00:00:02"
            actions:
                allow: 1
                output:
                    dl_dst: "00:00:00:00:00:03"
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

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        # we expect to see the rewritten mac address.
        tcpdump_filter = ('icmp and ether dst 00:00:00:00:00:03')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '00:00:00:00:00:02')),
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))

    def verify_dest_rewrite(self, first_host, second_host, third_host, tcpdump_host):
        second_host.setMAC('00:00:00:00:00:02')
        third_host.setMAC('00:00:00:00:00:03')
        # get the switch to port/mac learn a host.
        # let h1 think h3 is @ h2.mac, the acl should change the dst mac,
        #  so that h3 will receive it and reply.
        third_host.cmd('arp -s %s %s' % (second_host.IP(), second_host.MAC()))
        third_host.cmd('ping -c1 %s' % second_host.IP())
        self.wait_until_matching_flow(
            r'OUTPUT:3.+table_id": 6.+dl_dst": "00:00:00:00:00:03"',
            timeout=2)
        tcpdump_filter = ('icmp and ether src %s and ether dst %s' % (
            first_host.MAC(), third_host.MAC()))
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (third_host.IP(), second_host.MAC())),
                # this will fail if no reply
                lambda: self.one_ipv4_ping(first_host, third_host.IP(), require_host_learned=False)])
        # ping from h1 to h2.mac should appear in third host, and not second host, as
        # the acl should rewrite the dst mac.
        self.assertFalse(re.search(
            '%s: ICMP echo request' % third_host.IP(), tcpdump_txt))

    def test_switching(self):
        """Tests that a acl can rewrite the destination mac address,
           and the packet will only go out the port of the new mac.
           (Continues through faucet pipeline)
        """
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.verify_dest_rewrite(first_host, second_host, third_host, second_host)

    def test_switching1(self):
        """Same as test_switching(), except changed what host the tcpdump is done on.
           Quick check until make tcpdump_helper (or similar) do multiple interfaces.
           Tests that a acl can rewrite the destination mac address,
           and the packet will only go out the port of the new mac.
           (Continues through faucet pipeline)
        """
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.verify_dest_rewrite(first_host, second_host, third_host, third_host)


def import_hw_config():
    """Import configuration for physical switch testing."""
    for config_file_dir in CONFIG_FILE_DIRS:
        config_file_name = os.path.join(config_file_dir, HW_SWITCH_CONFIG_FILE)
        if os.path.isfile(config_file_name):
            break
    if os.path.isfile(config_file_name):
        print('Using config from %s' % config_file_name)
    else:
        print('Cannot find %s in %s' % (HW_SWITCH_CONFIG_FILE, CONFIG_FILE_DIRS))
        sys.exit(-1)
    try:
        with open(config_file_name, 'r') as config_file:
            config = yaml.load(config_file)
    except:
        print('Could not load YAML config data from %s' % config_file_name)
        sys.exit(-1)
    if 'hw_switch' in config and config['hw_switch']:
        required_config = ('dp_ports', 'cpn_intf', 'dpid', 'of_port', 'gauge_of_port')
        for required_key in required_config:
            if required_key not in config:
                print('%s must be specified in %s to use HW switch.' % (
                    required_key, config_file_name))
                sys.exit(-1)
        dp_ports = config['dp_ports']
        if len(dp_ports) != REQUIRED_TEST_PORTS:
            print('Exactly %u dataplane ports are required, '
                  '%d are provided in %s.' %
                  (REQUIRED_TEST_PORTS, len(dp_ports), config_file_name))
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
            print('could not run %s' % required_binary)
            return False
        present_match = re.search(binary_present_re, binary_output)
        if not present_match:
            print('%s not present or did not return expected string %s' % (
                required_binary, binary_present_re))
            return False
        if binary_version_re:
            version_match = re.search(binary_version_re, binary_output)
            if version_match is None:
                print('could not get version from %s (%s)' % (
                    required_binary, binary_output))
                return False
            try:
                binary_version = version_match.group(1)
            except ValueError:
                print('cannot parse version %s for %s' % (
                    version_match, required_binary))
                return False
            if version.parse(binary_version) < version.parse(binary_minversion):
                print('%s version %s is less than required version %s' % (
                    required_binary, binary_version, binary_minversion))
                return False
            print('%s version is %s' % (required_binary, binary_version))
        else:
            print('%s present (%s)' % (required_binary, binary_present_re))
    return True


def lint_check():
    """Run pylint on required source files."""
    for faucet_src in FAUCET_LINT_SRCS + FAUCET_TEST_LINT_SRCS:
        ret = subprocess.call(['pylint', '-E', faucet_src])
        if ret:
            print(('pylint of %s returns an error' % faucet_src))
            return False
    for faucet_src in FAUCET_LINT_SRCS:
        output_2to3 = subprocess.check_output(
            ['2to3', '--nofix=import', faucet_src],
            stderr=open(os.devnull, 'wb'))
        if output_2to3:
            print(('2to3 of %s returns a diff (not python3 compatible)' % faucet_src))
            print(output_2to3)
            return False
    return True


def make_suite(tc_class, hw_config, root_tmpdir, ports_sock):
    """Compose test suite based on test class names."""
    testloader = unittest.TestLoader()
    testnames = testloader.getTestCaseNames(tc_class)
    suite = unittest.TestSuite()
    for name in testnames:
        suite.addTest(tc_class(name, hw_config, root_tmpdir, ports_sock))
    return suite


def pipeline_superset_report(root_tmpdir):
    ofchannel_logs = glob.glob(
        os.path.join(root_tmpdir, '*/ofchannel.log'))
    match_re = re.compile(
        r'^.+types table: (\d+) match: (.+) instructions: (.+) actions: (.+)')
    table_matches = collections.defaultdict(set)
    table_instructions = collections.defaultdict(set)
    table_actions = collections.defaultdict(set)
    for log in ofchannel_logs:
        for log_line in open(log).readlines():
            match = match_re.match(log_line)
            if match:
                table, matches, instructions, actions = match.groups()
                table = int(table)
                table_matches[table].update(eval(matches))
                table_instructions[table].update(eval(instructions))
                table_actions[table].update(eval(actions))
    print('')
    for table in sorted(table_matches):
        print('table: %u' % table)
        print('  matches: %s' % sorted(table_matches[table]))
        print('  table_instructions: %s' % sorted(table_instructions[table]))
        print('  table_actions: %s' % sorted(table_actions[table]))


def run_tests(requested_test_classes,
              excluded_test_classes,
              keep_logs,
              serial,
              hw_config):
    """Actually run the test suites, potentially in parallel."""
    if hw_config is not None:
        print('Testing hardware, forcing test serialization')
        serial = True
    root_tmpdir = tempfile.mkdtemp(prefix='faucet-tests-')
    ports_sock = os.path.join(root_tmpdir, 'ports-server')
    ports_server = threading.Thread(
        target=faucet_mininet_test_util.serve_ports, args=(ports_sock,))
    ports_server.setDaemon(True)
    ports_server.start()
    sanity_tests = unittest.TestSuite()
    single_tests = unittest.TestSuite()
    parallel_tests = unittest.TestSuite()
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if not inspect.isclass(obj):
            continue
        if requested_test_classes and name not in requested_test_classes:
            continue
        if excluded_test_classes and name in excluded_test_classes:
            continue
        if name.endswith('Test') and name.startswith('Faucet'):
            # TODO: hardware testing should have a way to configure
            # which switch in a string is the hardware switch to test.
            if re.search(r'Faucet.*String', name) and hw_config is not None:
                print(
                    'skipping %s as string tests not supported for hardware' % name)
                continue
            print('adding test %s' % name)
            test_suite = make_suite(obj, hw_config, root_tmpdir, ports_sock)
            if name.startswith('FaucetSanity'):
                sanity_tests.addTest(test_suite)
            else:
                if serial or name.startswith('FaucetSingle'):
                    single_tests.addTest(test_suite)
                else:
                    parallel_tests.addTest(test_suite)
    all_successful = True
    sanity_runner = unittest.TextTestRunner(verbosity=255, failfast=True)
    sanity_result = sanity_runner.run(sanity_tests)
    if sanity_result.wasSuccessful():
        print('running %u tests in parallel and %u tests serial' % (
            parallel_tests.countTestCases(), single_tests.countTestCases()))
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
                all_successful = False
                print(result.printErrors())
        pipeline_superset_report(root_tmpdir)
    else:
        print('sanity tests failed - test environment not correct')

    os.remove(ports_sock)
    if not keep_logs and all_successful:
        shutil.rmtree(root_tmpdir)


def parse_args():
    """Parse command line arguments."""
    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "cksx:", ["clean", "keep_logs", "serial"])
    except getopt.GetoptError as err:
        print(str(err))
        sys.exit(2)

    clean = False
    keep_logs = False
    serial = False
    excluded_test_classes = []

    for opt, arg in opts:
        if opt in ('-c', '--clean'):
            clean = True
        if opt in ('-k', '--keep_logs'):
            keep_logs = True
        if opt in ('-s', '--serial'):
            serial = True
        if opt == '-x':
            excluded_test_classes.append(arg)

    return (args, clean, keep_logs, serial, excluded_test_classes)


def test_main():
    """Test main."""
    setLogLevel('info')
    args, clean, keep_logs, serial, excluded_test_classes = parse_args()

    if clean:
        print('Cleaning up test interfaces, processes and openvswitch '
              'configuration from previous test runs')
        Cleanup.cleanup()
        sys.exit(0)
    if not check_dependencies():
        print('dependency check failed. check required library/binary '
              'list in header of this script')
        sys.exit(-1)
    if not lint_check():
        print('pylint must pass with no errors')
        sys.exit(-1)
    hw_config = import_hw_config()
    run_tests(args, excluded_test_classes, keep_logs, serial, hw_config)


if __name__ == '__main__':
    test_main()
