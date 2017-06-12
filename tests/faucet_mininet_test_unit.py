#!/usr/bin/env python

"""Mininet tests for FAUCET."""

# pylint: disable=missing-docstring

import os
import random
import re
import shutil
import threading
import time
import unittest

from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer

import ipaddress
import yaml

from mininet.net import Mininet

import faucet_mininet_test_base
import faucet_mininet_test_util
import faucet_mininet_test_topo


class FaucetTest(faucet_mininet_test_base.FaucetTestBase):

    pass


@unittest.skip('currently flaky')
class FaucetAPITest(faucet_mininet_test_base.FaucetTestBase):
    """Test the Faucet API."""

    def setUp(self):
        self.tmpdir = self._tmpdir_name()
        name = 'faucet'
        self._set_var_path(name, 'FAUCET_CONFIG', 'config/testconfigv2-simple.yaml')
        self._set_var_path(name, 'FAUCET_LOG', 'faucet.log')
        self._set_var_path(name, 'FAUCET_EXCEPTION_LOG', 'faucet-exception.log')
        self._set_var_path(name, 'API_TEST_RESULT', 'result.txt')
        self.results_file = self.env[name]['API_TEST_RESULT']
        shutil.copytree('config', os.path.join(self.tmpdir, 'config'))
        self.dpid = str(0xcafef00d)
        self._set_prom_port(name)
        self.of_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock, self._test_name())
        self.topo = faucet_mininet_test_topo.FaucetSwitchTopo(
            self.ports_sock,
            dpid=self.dpid,
            n_untagged=7,
            test_name=self._test_name())
        self.net = Mininet(
            self.topo,
            controller=faucet_mininet_test_topo.FaucetAPI(
                name=name,
                tmpdir=self.tmpdir,
                env=self.env[name],
                port=self.of_port))
        self.net.start()
        self.wait_for_tcp_listen(self._get_controller(), self.of_port)

    def test_api(self):
        for _ in range(10):
            try:
                with open(self.results_file, 'r') as results:
                    result = results.read().strip()
                    self.assertEquals('pass', result, result)
                    return
            except IOError:
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


class FaucetUntaggedTcpIPv4IperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        second_host_ip = ipaddress.ip_address(unicode(second_host.IP()))
        for _ in range(3):
            self.ping_all_when_learned()
            self.one_ipv4_ping(first_host, second_host_ip)
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                1, second_host_ip)
            self.flap_all_switch_ports()


class FaucetUntaggedTcpIPv6IperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        first_host_ip = ipaddress.ip_interface(u'fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface(u'fc00::1:2/112')
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        for _ in range(3):
            self.ping_all_when_learned()
            self.one_ipv6_ping(first_host, second_host_ip.ip)
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                1, second_host_ip.ip)
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
        self.verify_no_exception(self.env['faucet']['FAUCET_EXCEPTION_LOG'])

    def test_untagged(self):

        influx_log = os.path.join(self.tmpdir, 'influx.log')

        class PostHandler(SimpleHTTPRequestHandler):

            def do_POST(self):
                content_len = int(self.headers.getheader('content-length', 0))
                content = self.rfile.read(content_len)
                open(influx_log, 'a').write(content)
                return self.send_response(204)

        server = HTTPServer(('', self.influx_port), PostHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        self.ping_all_when_learned()
        for _ in range(3):
            if os.path.exists(influx_log):
                break
            time.sleep(2)
        server.shutdown()
        self.assertTrue(os.path.exists(influx_log))


class FaucetNailedForwardingTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
                output:
                    port: b2
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
    2:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    port: b1
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    port: b1
        - rule:
            actions:
                allow: 0
    3:
        - rule:
            actions:
                allow: 0
    4:
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
                acl_in: 2
            b3:
                number: %(port_3)d
                native_vlan: 100
                acl_in: 3
            b4:
                number: %(port_4)d
                native_vlan: 100
                acl_in: 4
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
        self.assertEquals(2, self.scrape_prometheus_var(
            'vlan_hosts_learned', {'vlan': '100'}))


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
        flows = self.get_matching_flows_on_dpid(
            self.dpid,
            {u'dl_vlan': u'100', u'in_port': int(self.port_map['port_2'])},
            table_id=3)
        self.assertEquals(self.MAX_HOSTS, len(flows))
        self.assertEquals(
            self.MAX_HOSTS,
            len(self.scrape_prometheus_var(
                'learned_macs',
                {'port': self.port_map['port_2'], 'vlan': '100'},
                multiple=True)))


class FaucetHostsTimeoutPrometheusTest(FaucetUntaggedTest):
    """Test for hosts that have been learnt are exported via prometheus.
       Hosts should timeout, and the exported prometheus values should
       be overwritten.
       If the maximum number of MACs at any one time is 5, then only 5 values
       should be exported, even if over 2 hours, there are 100 MACs learnt
    """
    TIMEOUT = 10
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        timeout: 10
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
        return long(mac.replace(':', ''), 16)

    def macs_learned_on_port(self, port):
        port_learned_macs_prom = self.scrape_prometheus_var(
            'learned_macs', {'port': str(port), 'vlan': '100'},
            default=[], multiple=True)
        macs_learned = []
        for _, mac_int in port_learned_macs_prom:
            if mac_int:
                macs_learned.append(mac_int)
        return macs_learned

    def verify_hosts_learned(self, hosts):
        """Check that hosts are learned by FAUCET on the expected ports."""
        mac_ints_on_port_learned = {}
        for mac, port in hosts.items():
            self.mac_learned(mac)
            if port not in mac_ints_on_port_learned:
                mac_ints_on_port_learned[port] = set()
            macs_learned = self.macs_learned_on_port(port)
            mac_ints_on_port_learned[port].update(macs_learned)
        for mac, port in hosts.items():
            mac_int = self.mac_as_int(mac)
            self.assertTrue(mac_int in mac_ints_on_port_learned[port])

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        learned_mac_ports = {}
        learned_mac_ports[first_host.MAC()] = self.port_map['port_1']
        mac_intfs = []
        mac_ips = []

        for i in range(10, 16):
            if i == 14:
                first_host.cmd('fping -c3 %s' % ' '.join(mac_ips))
                # check first 4 are learnt
                self.verify_hosts_learned(learned_mac_ports)
                learned_mac_ports = {}
                mac_intfs = []
                mac_ips = []
                # wait for first lot to time out.
                # Adding 11 covers the random variation when a rule is added
                time.sleep(self.TIMEOUT + 11)
            mac_intf = 'mac%u' % i
            mac_intfs.append(mac_intf)
            mac_ipv4 = '10.0.0.%u' % i
            mac_ips.append(mac_ipv4)
            second_host.cmd('ip link add link %s %s type macvlan' % (
                second_host.defaultIntf(), mac_intf))
            second_host.cmd('ip address add %s/24 dev %s' % (
                mac_ipv4, mac_intf))
            address = second_host.cmd(
                '|'.join((
                    'ip link show %s' % mac_intf,
                    'grep -o "..:..:..:..:..:.."',
                    'head -1',
                    'xargs echo -n')))
            learned_mac_ports[address] = self.port_map['port_2']
            second_host.cmd('ip link set dev %s up' % mac_intf)

        first_host.cmd('fping -c3 %s' % ' '.join(mac_ips))
        learned_mac_ports[first_host.MAC()] = self.port_map['port_1']
        self.verify_hosts_learned(learned_mac_ports)
        # Verify same or less number of hosts on a port reported by Prometheus
        self.assertTrue((
            len(self.macs_learned_on_port(self.port_map['port_1'])) <=
            len(learned_mac_ports)))


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
        self.assertGreater(
            self.scrape_prometheus_var('vlan_hosts_learned', {'vlan': '100'}),
            self.MAX_HOSTS)


class FaucetUntaggedHUPTest(FaucetUntaggedTest):
    """Test handling HUP signal without config change."""

    def test_untagged(self):
        """Test that FAUCET receives HUP signal and keeps switching."""
        init_config_count = self.get_configure_count()
        for i in range(init_config_count, init_config_count+3):
            configure_count = self.get_configure_count()
            self.assertEquals(i, configure_count)
            self.verify_hup_faucet()
            configure_count = self.get_configure_count()
            self.assertTrue(i + 1, configure_count)
            self.assertEqual(
                self.scrape_prometheus_var('of_dp_disconnections', default=0),
                0)
            self.assertEqual(
                self.scrape_prometheus_var('of_dp_connections', default=0),
                1)
            self.wait_until_controller_flow()
            self.ping_all_when_learned()


class FaucetConfigReloadTest(FaucetTest):
    """Test handling HUP signal with config change."""

    N_UNTAGGED = 4
    N_TAGGED = 0
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
    200:
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
        open(self.faucet_config_path, 'a').write(
            'include:\n     - %s' % self.acl_config_file)
        self.topo = self.topo_class(
            self.ports_sock, dpid=self.dpid,
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED)
        self.start_net()

    def _get_conf(self):
        return yaml.load(open(self.faucet_config_path, 'r').read())

    def _reload_conf(self, conf, restart):
        open(self.faucet_config_path, 'w').write(yaml.dump(conf))
        if restart:
            self.verify_hup_faucet()

    def get_port_match_flow(self, port_no, table_id=3):
        flow = self.get_matching_flow_on_dpid(
            self.dpid, {u'in_port': int(port_no)}, table_id)
        return flow

    def change_port_config(self, port, config_name, config_value,
                           restart=True, conf=None):
        if conf is None:
            conf = self._get_conf()
        conf['dps']['faucet-1']['interfaces'][port][config_name] = config_value
        self._reload_conf(conf, restart)

    def change_vlan_config(self, vlan, config_name, config_value,
                           restart=True, conf=None):
        if conf is None:
            conf = self._get_conf()
        conf['vlans'][vlan][config_name] = config_value
        self._reload_conf(conf, restart)

    def test_port_change_vlan(self):
        first_host, second_host = self.net.hosts[:2]
        third_host, fourth_host = self.net.hosts[2:]
        self.ping_all_when_learned()
        self.change_port_config(
            self.port_map['port_1'], 'native_vlan', 200, restart=False)
        self.change_port_config(
            self.port_map['port_2'], 'native_vlan', 200, restart=True)
        for port_name in ('port_1', 'port_2'):
            self.wait_until_matching_flow(
                {u'in_port': int(self.port_map[port_name])},
                table_id=1,
                actions=[u'SET_FIELD: {vlan_vid:4296}'])
        self.one_ipv4_ping(first_host, second_host.IP(), require_host_learned=False)
        # hosts 1 and 2 now in VLAN 200, so they shouldn't see floods for 3 and 4.
        self.verify_vlan_flood_limited(
            third_host, fourth_host, first_host)

    def test_port_change_acl(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        orig_conf = self._get_conf()
        self.change_port_config(self.port_map['port_1'], 'acl_in', 1)
        self.wait_until_matching_flow(
            {u'in_port': int(self.port_map['port_1']), u'tp_dst': 5001}, table_id=0)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)
        self._reload_conf(orig_conf, True)
        self.verify_tp_dst_notblocked(
            5001, first_host, second_host, table_id=None)
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=None)

    def test_port_change_permanent_learn(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.change_port_config(self.port_map['port_1'], 'permanent_learn', True)
        self.ping_all_when_learned()
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned()
        self.change_port_config(
            self.port_map['port_1'], 'acl_in', 1)
        self.wait_until_matching_flow(
            {u'in_port': int(self.port_map['port_1']), u'tp_dst': 5001},
            table_id=0)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetUntaggedBGPIPv4DefaultRouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import default route from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: %(bgp_port)d
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
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
  neighbor 127.0.0.1 {
    local-address 127.0.0.1;
    connect %(bgp_port)d;
    peer-as 1;
    local-as 2;
    static {
      route 0.0.0.0/0 next-hop 10.0.0.1 local-preference 100;
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
        first_host_alias_ip = ipaddress.ip_interface(u'10.99.99.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.wait_bgp_up('127.0.0.1', 100)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV4.ip)
        self.one_ipv4_ping(second_host, first_host_alias_ip.ip)
        self.one_ipv4_controller_ping(first_host)


class FaucetUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: %(bgp_port)d
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
    local-address 127.0.0.1;
    connect %(bgp_port)d;
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
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route('10.0.0.4/24 cannot be us')
        self.verify_invalid_bgp_route('10.0.0.5/24 is not a connected network')
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv4Network(u'10.0.3.0/24'))
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        for host in first_host, second_host:
            self.one_ipv4_controller_ping(host)


class FaucetUntaggedIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and export to BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: %(bgp_port)d
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
    local-address 127.0.0.1;
    connect %(bgp_port)d;
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
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        # exabgp should have received our BGP updates
        updates = self.exabgp_updates(self.exabgp_log)
        assert re.search('10.0.0.0/24 next-hop 10.0.0.254', updates)
        assert re.search('10.0.1.0/24 next-hop 10.0.0.1', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)
        assert re.search('10.0.2.0/24 next-hop 10.0.0.2', updates)


class FaucetZodiacUntaggedIPv4RouteTest(FaucetUntaggedIPv4RouteTest):

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
        self.ping_all_when_learned()
        self.verify_port1_unicast(True)
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
        self.verify_port1_unicast(False)
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
        self.verify_port1_unicast(False)
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
        self.verify_port1_unicast(False)
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


class FaucetUntaggedIPv6RATest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fe80::1:254/64", "fc00::1:254/112", "fc00::2:254/112", "10.0.0.254/24"]
"""

    CONFIG = """
        advertise_interval: 5
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

    def test_ndisc6(self):
        first_host = self.net.hosts[0]
        for vip in ('fe80::1:254', 'fc00::1:254', 'fc00::2:254'):
            self.assertEquals(
                '0E:00:00:00:00:01',
                first_host.cmd('ndisc6 -q %s %s' % (vip, first_host.defaultIntf())).strip())

    def test_rdisc6(self):
        first_host = self.net.hosts[0]
        rdisc6_results = sorted(list(set(first_host.cmd(
            'rdisc6 -q %s' % first_host.defaultIntf()).splitlines())))
        self.assertEquals(
            ['fc00::1:0/112', 'fc00::2:0/112'],
            rdisc6_results)

    def test_ra_advertise(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = ' and '.join((
            'ether dst 33:33:00:00:00:01',
            'ether src 0e:00:00:00:00:01',
            'icmp6',
            'ip6[40] == 134',
            'ip6 host fe80::1:254'))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [], timeout=30, vflags='-vv', packets=1)
        for ra_required in (
                r'fe80::1:254 > ff02::1:.+ICMP6, router advertisement',
                r'fc00::1:0/112, Flags \[onlink, auto\]',
                r'fc00::2:0/112, Flags \[onlink, auto\]',
                r'source link-address option \(1\), length 8 \(1\): 0e:00:00:00:00:01'):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg='%s: %s' % (ra_required, tcpdump_txt))

    def test_rs_reply(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = ' and '.join((
            'ether src 0e:00:00:00:00:01',
            'ether dst %s' % first_host.MAC(),
            'icmp6',
            'ip6[40] == 134',
            'ip6 host fe80::1:254'))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'rdisc6 -1 %s' % first_host.defaultIntf())],
            timeout=30, vflags='-vv', packets=1)
        for ra_required in (
                r'fe80::1:254 > fe80::.+ICMP6, router advertisement',
                r'fc00::1:0/112, Flags \[onlink, auto\]',
                r'fc00::2:0/112, Flags \[onlink, auto\]',
                r'source link-address option \(1\), length 8 \(1\): 0e:00:00:00:00:01'):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg='%s: %s (%s)' % (ra_required, tcpdump_txt, tcpdump_filter))


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
        self.verify_vlan_flood_limited(
            tagged_host_pair[0], tagged_host_pair[1], untagged_host_pair[0])
        self.verify_vlan_flood_limited(
            untagged_host_pair[0], untagged_host_pair[1], tagged_host_pair[0])
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


class FaucetUntaggedVLANACLTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
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
vlans:
    100:
        description: "untagged"
        acl_in: 1
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

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(
            5001, first_host, second_host, table_id=2)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=2)


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
                lambda: first_host.cmd(
                    'ping -c1 %s' % second_host.IP())], packets=10, root_intf=True)
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


class FaucetTaggedProactiveNeighborIPv4RouteTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn: true
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
        first_host_alias_ip = ipaddress.ip_interface(u'10.0.0.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.add_host_route(second_host, first_host_alias_host_ip, self.FAUCET_VIPV4.ip)
        self.one_ipv4_ping(second_host, first_host_alias_ip.ip)
        self.assertGreater(
            self.scrape_prometheus_var(
                'vlan_neighbors', {'ipv': '4', 'vlan': '100'}),
            1)


class FaucetTaggedProactiveNeighborIPv6RouteTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["fc00::1:3/64"]
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn: true
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
        first_host_alias_ip = ipaddress.ip_interface(u'fc00::1:99/64')
        faucet_vip_ip = ipaddress.ip_interface(u'fc00::1:3/126')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.add_host_ipv6_address(first_host, ipaddress.ip_interface(u'fc00::1:1/64'))
        # We use a narrower mask to force second_host to use the /128 route,
        # since otherwise it would realize :99 is directly connected via ND and send direct.
        self.add_host_ipv6_address(second_host, ipaddress.ip_interface(u'fc00::1:2/126'))
        self.add_host_ipv6_address(first_host, first_host_alias_ip)
        self.add_host_route(second_host, first_host_alias_host_ip, faucet_vip_ip.ip)
        self.one_ipv6_ping(second_host, first_host_alias_ip.ip)
        self.assertGreater(
            self.scrape_prometheus_var(
                'vlan_neighbors', {'ipv': '6', 'vlan': '100'}),
            1)


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


class FaucetUntaggedBGPIPv6DefaultRouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: %(bgp_port)d
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
    local-address ::1;
    connect %(bgp_port)d;
    peer-as 1;
    local-as 2;
    static {
      route ::/0 next-hop fc00::1:1 local-preference 100;
    }
  }
}
"""

    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf)

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        first_host_alias_ip = ipaddress.ip_interface(u'fc00::50:1/112')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.add_host_ipv6_address(first_host, first_host_alias_ip)
        self.wait_bgp_up('::1', 100)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV6.ip)
        self.one_ipv6_ping(second_host, first_host_alias_ip.ip)
        self.one_ipv6_controller_ping(first_host)


class FaucetUntaggedBGPIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: %(bgp_port)d
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
    local-address ::1;
    connect %(bgp_port)d;
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
        self.exabgp_log = self.start_exabgp(self.exabgp_conf)

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.wait_bgp_up('::1', 100)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route('fc00::40:1/112 cannot be us')
        self.verify_invalid_bgp_route('fc00::50:1/112 is not a connected network')
        self.verify_ipv6_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv6_routing_mesh()
        for host in first_host, second_host:
            self.one_ipv6_controller_ping(host)


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


class FaucetUntaggedIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: %(bgp_port)d
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
    local-address ::1;
    connect %(bgp_port)d;
    peer-as 1;
    local-as 2;
  }
}
"""
    exabgp_log = None

    def pre_start_net(self):
        self.exabgp_log = self.start_exabgp(self.exabgp_conf)

    def test_untagged(self):
        self.verify_ipv6_routing_mesh()
        second_host = self.net.hosts[1]
        self.flap_all_switch_ports()
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv6Network(u'fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        self.wait_bgp_up('::1', 100)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        updates = self.exabgp_updates(self.exabgp_log)
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
        open(self.faucet_config_path, 'w').write(self.CONFIG)
        self.topo = faucet_mininet_test_topo.FaucetStringOfDPSwitchTopo(
            self.ports_sock,
            dpids=self.dpids,
            n_tagged=n_tagged,
            tagged_vid=tagged_vid,
            n_untagged=n_untagged,
            test_name=self._test_name(),
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

    def matching_flow_present(self, match, timeout=10, table_id=None,
                              actions=None, match_exact=None):
        """Find the first DP that has a flow that matches match."""
        for dpid in self.dpids:
            if self.matching_flow_present_on_dpid(
                    dpid, match, timeout=timeout,
                    table_id=table_id, actions=actions,
                    match_exact=match_exact):
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


class FaucetStringOfDPACLOverrideTest(FaucetStringOfDPTest):

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
                {u'dl_vlan': u'100', u'dl_dst': u'ff:ff:ff:ff:ff:ff'},
                table_id=7))


class FaucetGroupTableUntaggedIPv4RouteTest(FaucetUntaggedTest):

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


class FaucetGroupUntaggedIPv6RouteTest(FaucetUntaggedTest):

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


class FaucetEthSrcMaskTest(FaucetUntaggedTest):
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            eth_src: 0e:0d:00:00:00:00/ff:ff:00:00:00:00
            actions:
                allow: 1
        - rule:
            actions:
                allow: 0
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
        first_host.setMAC('0e:0d:00:00:00:99')
        self.assertEqual(0, self.net.ping((first_host, second_host)))
        self.wait_nonzero_packet_count_flow(
            {u'dl_src': u'0e:0d:00:00:00:00/ff:ff:00:00:00:00'}, table_id=0)


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

    def verify_dest_rewrite(self, source_host, overridden_host, rewrite_host, tcpdump_host):
        overridden_host.setMAC('00:00:00:00:00:02')
        rewrite_host.setMAC('00:00:00:00:00:03')
        rewrite_host.cmd('arp -s %s %s' % (overridden_host.IP(), overridden_host.MAC()))
        rewrite_host.cmd('ping -c1 %s' % overridden_host.IP())
        self.wait_until_matching_flow(
            {u'dl_dst': u'00:00:00:00:00:03'},
            table_id=6,
            actions=[u'OUTPUT:%u' % self.port_map['port_3']])
        tcpdump_filter = ('icmp and ether src %s and ether dst %s' % (
            source_host.MAC(), rewrite_host.MAC()))
        tcpdump_txt = self.tcpdump_helper(
            tcpdump_host, tcpdump_filter, [
                lambda: source_host.cmd(
                    'arp -s %s %s' % (rewrite_host.IP(), overridden_host.MAC())),
                # this will fail if no reply
                lambda: self.one_ipv4_ping(
                    source_host, rewrite_host.IP(), require_host_learned=False)])
        # ping from h1 to h2.mac should appear in third host, and not second host, as
        # the acl should rewrite the dst mac.
        self.assertFalse(re.search(
            '%s: ICMP echo request' % rewrite_host.IP(), tcpdump_txt))

    def test_switching(self):
        """Tests that a acl can rewrite the destination mac address,
           and the packet will only go out the port of the new mac.
           (Continues through faucet pipeline)
        """
        source_host, overridden_host, rewrite_host = self.net.hosts[0:3]
        self.verify_dest_rewrite(
            source_host, overridden_host, rewrite_host, overridden_host)
