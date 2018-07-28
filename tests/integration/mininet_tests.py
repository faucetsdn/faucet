#!/usr/bin/env python

"""Mininet tests for FAUCET."""

# pylint: disable=missing-docstring
# pylint: disable=too-many-arguments

import binascii
import itertools
import json
import os
import random
import re
import socket
import threading
import time
import unittest2

from SimpleHTTPServer import SimpleHTTPRequestHandler
from BaseHTTPServer import HTTPServer

import ipaddress
import yaml
import scapy.all

from mininet.log import error, output
from mininet.net import Mininet

from clib import mininet_test_base
from clib import mininet_test_util
from clib import mininet_test_topo

from clib.mininet_test_base import PEER_BGP_AS


class QuietHTTPServer(HTTPServer):

    allow_reuse_address = True
    timeout = None

    @staticmethod
    def handle_error(_request, _client_address):
        return


class PostHandler(SimpleHTTPRequestHandler):

    @staticmethod
    def log_message(_format, *_args):
        return

    def _log_post(self):
        content_len = int(self.headers.getheader('content-length', 0))
        content = self.rfile.read(content_len).strip()
        if content and hasattr(self.server, 'influx_log'):
            with open(self.server.influx_log, 'a') as influx_log:
                influx_log.write(content + '\n')


class InfluxPostHandler(PostHandler):

    def do_POST(self): # pylint: disable=invalid-name
        self._log_post()
        return self.send_response(204)


class SlowInfluxPostHandler(PostHandler):

    def do_POST(self): # pylint: disable=invalid-name
        self._log_post()
        time.sleep(self.server.timeout * 3)
        return self.send_response(500)


class FaucetTest(mininet_test_base.FaucetTestBase):

    pass


class FaucetUntaggedTest(FaucetTest):
    """Basic untagged VLAN test."""

    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
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

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetUntaggedTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def verify_events_log(self, event_log):
        required_events = set(['PORT_CHANGE', 'L2_LEARN', 'PORTS_STATUS'])
        for _ in range(10):
            prom_event_id = self.scrape_prometheus_var('faucet_event_id', dpid=False)
            event_id = None
            with open(event_log, 'r') as event_log_file:
                for event_log_line in event_log_file.readlines():
                    event = json.loads(event_log_line.strip())
                    event_id = event['event_id']
                    for required_event in list(required_events):
                        if required_event in required_events:
                            required_events.remove(required_event)
                            break
            if prom_event_id == event_id:
                return
            time.sleep(1)
        self.assertEqual(prom_event_id, event_id)
        self.assertFalse(required_events)

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        event_log = os.path.join(self.tmpdir, 'event.log')
        controller = self._get_controller()
        sock = self.env['faucet']['FAUCET_EVENT_SOCK']
        controller.cmd(mininet_test_util.timeout_cmd(
            'nc -U %s > %s &' % (sock, event_log), 120))
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.gauge_smoke_test()
        self.prometheus_smoke_test()
        self.assertGreater(os.path.getsize(event_log), 0)
        controller.cmd(
            mininet_test_util.timeout_cmd(
                'nc -U %s' % sock, 10))
        self.verify_events_log(event_log)


class FaucetUntagged8021XTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    eapol_to_nfv:
        - rule:
            dl_type: 0x888e
            actions:
                output:
                    set_fields:
                        - eth_dst: 00:00:00:00:00:01
                    port: b4
        - rule:
            actions:
                allow: 1
    eapol_from_nfv:
        - rule:
            dl_type: 0x888e
            eth_dst: 00:00:00:00:00:01
            actions:
                output:
                    set_fields:
                        - eth_dst: 01:80:c2:00:00:03
                    port: b1
        - rule:
            actions:
                allow: 0
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        dot1x:
            nfv_intf: NFV_INTF
        interfaces:
            %(port_1)d:
                name: b1
                native_vlan: 100
                description: "b1 - 802.1x client."
                acl_in: eapol_to_nfv
                dot1x: True
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                name: b4
                native_vlan: 100
                description: "NFV host - interface used by controller."
                acl_in: eapol_from_nfv
"""

    wpasupplicant_conf = """
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="user@example.com"
    password="microphone"
}
"""

    eapol_host = None
    ping_host = None
    nfv_host = None
    nfv_intf = None

    def _write_faucet_config(self):
        self.eapol_host = self.net.hosts[0]
        self.ping_host = self.net.hosts[1]
        self.nfv_host = self.net.hosts[-1]
        switch = self.net.switches[0]
        last_host_switch_link = switch.connectionsTo(self.nfv_host)[0]
        self.nfv_intf = str([
            intf for intf in last_host_switch_link if intf in switch.intfList()][0])
        self.CONFIG = self.CONFIG.replace('NFV_INTF', self.nfv_intf)
        super(FaucetUntagged8021XTest, self)._write_faucet_config()

    def setUp(self):
        super(FaucetUntagged8021XTest, self).setUp()
        self.host_drop_all_ips(self.nfv_host)

    def test_untagged(self):
        return


class FaucetUntaggedRandomVidTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    randvlan:
        vid: 100
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: randvlan
                description: "b1"
            %(port_2)d:
                native_vlan: randvlan
                description: "b2"
            %(port_3)d:
                native_vlan: randvlan
                description: "b3"
            %(port_4)d:
                native_vlan: randvlan
                description: "b4"
"""

    def test_untagged(self):
        for _ in range(5):
            vid = random.randint(2, 512)
            self.change_vlan_config(
                'randvlan', 'vid', vid, cold_start=True, hup=True)
            self.ping_all_when_learned()


class FaucetUntaggedNoCombinatorialFlood(FaucetUntaggedTest):

    CONFIG = """
        combinatorial_port_flood: False
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


class FaucetUntaggedControllerNfvTest(FaucetUntaggedTest):

    # Name of switch interface connected to last host, accessible to controller.
    last_host_switch_intf = None

    def _write_faucet_config(self):
        last_host = self.net.hosts[-1]
        switch = self.net.switches[0]
        last_host_switch_link = switch.connectionsTo(last_host)[0]
        self.last_host_switch_intf = [intf for intf in last_host_switch_link if intf in switch.intfList()][0]
        # Now that interface is known, FAUCET config can be written to include it.
        super(FaucetUntaggedControllerNfvTest, self)._write_faucet_config()

    def test_untagged(self):
        super(FaucetUntaggedControllerNfvTest, self).test_untagged()
        # Confirm controller can see switch interface with traffic.
        ifconfig_output = self.net.controllers[0].cmd('ifconfig %s' % self.last_host_switch_intf)
        self.assertTrue(
            re.search('(R|T)X packets:[1-9]', ifconfig_output),
            msg=ifconfig_output)


class FaucetUntaggedBroadcastTest(FaucetUntaggedTest):

    UNICAST_MAC1 = '0e:00:00:00:00:02'
    UNICAST_MAC2 = '0e:00:00:00:00:03'

    def verify_unicast_not_looped(self, host):
        scapy_template = (
            'python -c \"from scapy.all import * ; '
            'sendp(Ether(src=\'%s\', dst=\'%s\')/'
            'IP(src=\'10.0.0.100\', dst=\'10.0.0.255\')/'
            'UDP(dport=9)/'
            'b\'hello\','
            'iface=\'%s\')\"')
        host.cmd(
            scapy_template % (
                self.UNICAST_MAC1, 'ff:ff:ff:ff:ff:ff', host.defaultIntf()))
        host.cmd(
            scapy_template % (
                self.UNICAST_MAC2, 'ff:ff:ff:ff:ff:ff', host.defaultIntf()))
        tcpdump_filter = '-Q in ether src %s' % self.UNICAST_MAC1
        tcpdump_txt = self.tcpdump_helper(
            host, tcpdump_filter, [
                lambda: host.cmd(
                    scapy_template % (
                        self.UNICAST_MAC1, self.UNICAST_MAC2, host.defaultIntf()))],
            timeout=5, vflags='-vv', packets=1)
        self.assertTrue(
            re.search('0 packets captured', tcpdump_txt), msg=tcpdump_txt)

    def test_untagged(self):
        super(FaucetUntaggedBroadcastTest, self).test_untagged()
        self.verify_broadcast()
        first_host = self.net.hosts[0]
        self.verify_no_bcast_to_self(first_host)
        self.verify_unicast_not_looped(first_host)


class FaucetUntaggedNoCombinatorialBroadcastTest(FaucetUntaggedBroadcastTest):

    CONFIG = """
        combinatorial_port_flood: False
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


class FaucetExperimentalAPITest(FaucetUntaggedTest):
    """Test the experimental Faucet API."""

    CONTROLLER_CLASS = mininet_test_topo.FaucetExperimentalAPI
    results_file = None

    def _set_static_vars(self):
        super(FaucetExperimentalAPITest, self)._set_static_vars()
        self._set_var_path('faucet', 'API_TEST_RESULT', 'result.txt')
        self.results_file = self.env['faucet']['API_TEST_RESULT']

    def test_untagged(self):
        result = None
        for _ in range(10):
            try:
                with open(self.results_file, 'r') as results:
                    result = results.read().strip()
                    if result == 'pass':
                        return
            except IOError:
                pass
            time.sleep(1)
        self.fail('incorrect result from API test: %s' % result)


class FaucetUntaggedLogRotateTest(FaucetUntaggedTest):

    def test_untagged(self):
        faucet_log = self.env['faucet']['FAUCET_LOG']
        self.assertTrue(os.path.exists(faucet_log))
        os.rename(faucet_log, faucet_log + '.old')
        self.assertTrue(os.path.exists(faucet_log + '.old'))
        self.flap_all_switch_ports()
        self.assertTrue(os.path.exists(faucet_log))


class FaucetUntaggedLLDPTest(FaucetUntaggedTest):

    CONFIG = """
        lldp_beacon:
            send_interval: 5
            max_per_interval: 5
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
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

    @staticmethod
    def wireshark_payload_format(payload_str):
        formatted_payload_str = ''
        groupsize = 4
        for payload_offset in range(len(payload_str) / groupsize): # pytype: disable=wrong-arg-types
            char_count = payload_offset * 2
            if char_count % 0x10 == 0:
                formatted_payload_str += '0x%4.4x: ' % char_count
            payload_fragment = payload_str[payload_offset * groupsize:][:groupsize]
            formatted_payload_str += ' ' + payload_fragment
        return formatted_payload_str

    def test_untagged(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = 'ether proto 0x88cc'
        timeout = 5 * 3
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd('sleep %u' % timeout)],
            timeout=timeout, vflags='-vv', packets=1)
        oui_prefix = ''.join(self.FAUCET_MAC.split(':')[:3])
        faucet_lldp_dp_id_attr = '%2.2x' % 1
        expected_lldp_dp_id = ''.join((
            oui_prefix,
            faucet_lldp_dp_id_attr,
            str(binascii.hexlify(str(self.dpid).encode('UTF-8')))))
        for lldp_required in (
                r'%s > 01:80:c2:00:00:0e, ethertype LLDP' % self.FAUCET_MAC,
                r'Application type \[voice\] \(0x01\), Flags \[Tagged\]Vlan id 50',
                r'System Name TLV \(5\), length 6: faucet',
                r'Port Description TLV \(4\), length 10: first_port',
                self.wireshark_payload_format(expected_lldp_dp_id)):
            self.assertTrue(
                re.search(lldp_required, tcpdump_txt),
                msg='%s: %s' % (lldp_required, tcpdump_txt))


class FaucetUntaggedLLDPDefaultFallbackTest(FaucetUntaggedTest):

    CONFIG = """
        lldp_beacon:
            send_interval: 5
            max_per_interval: 5
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                lldp_beacon:
                    enable: True
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
"""

    def test_untagged(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = 'ether proto 0x88cc'
        timeout = 5 * 3
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd('sleep %u' % timeout)],
            timeout=timeout, vflags='-vv', packets=1)
        for lldp_required in (
                r'%s > 01:80:c2:00:00:0e, ethertype LLDP' % self.FAUCET_MAC,
                r'Application type \[voice\] \(0x01\), Flags \[Tagged\]Vlan id 50',
                r'System Name TLV \(5\), length 8: faucet-1',
                r'Port Description TLV \(4\), length 2: b1'):
            self.assertTrue(
                re.search(lldp_required, tcpdump_txt),
                msg='%s: %s' % (lldp_required, tcpdump_txt))


class FaucetUntaggedMeterParseTest(FaucetUntaggedTest):

    REQUIRES_METERS = True
    OVS_TYPE = 'user'
    CONFIG_GLOBAL = """
meters:
    lossymeter:
        meter_id: 1
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 100
                    }
                ]
acls:
    lossyacl:
        - rule:
            actions:
                meter: lossymeter
                allow: 1
vlans:
    100:
        description: "untagged"
"""


class FaucetUntaggedApplyMeterTest(FaucetUntaggedMeterParseTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                acl_in: lossyacl
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
        super(FaucetUntaggedApplyMeterTest, self).test_untagged()
        first_host, second_host = self.net.hosts[:2]
        error('metered ping flood: %s' % first_host.cmd('ping -c 10000 -f %s' % second_host.IP()))


class FaucetUntaggedHairpinTest(FaucetUntaggedTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                hairpin: True
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
        # Create macvlan interfaces, with one in a separate namespace,
        # to force traffic between them to be hairpinned via FAUCET.
        first_host, second_host = self.net.hosts[:2]
        macvlan1_intf = 'macvlan1'
        macvlan1_ipv4 = '10.0.0.100'
        macvlan2_intf = 'macvlan2'
        macvlan2_ipv4 = '10.0.0.101'
        netns = first_host.name
        self.add_macvlan(first_host, macvlan1_intf, ipa=macvlan1_ipv4)
        self.add_macvlan(first_host, macvlan2_intf)
        macvlan2_mac = self.get_host_intf_mac(first_host, macvlan2_intf)
        if self.get_netns_list(first_host):
            first_host.cmd('ip netns del %s' % netns)
        self.assertEqual('', first_host.cmd('ip netns add %s' % netns))
        self.assertEqual('', first_host.cmd('ip link set %s netns %s' % (macvlan2_intf, netns)))
        for exec_cmd in (
                ('ip address add %s/24 brd + dev %s' % (
                    macvlan2_ipv4, macvlan2_intf),
                 'ip link set %s up' % macvlan2_intf)):
            self.assertEqual('', first_host.cmd('ip netns exec %s %s' % (netns, exec_cmd)))
        self.one_ipv4_ping(first_host, macvlan2_ipv4, intf=macvlan1_intf)
        self.one_ipv4_ping(first_host, second_host.IP())
        first_host.cmd('ip netns del %s' % netns)
        # Verify OUTPUT:IN_PORT flood rules are exercised.
        self.wait_nonzero_packet_count_flow(
            {u'in_port': self.port_map['port_1'],
             u'dl_dst': u'ff:ff:ff:ff:ff:ff'},
            table_id=self._FLOOD_TABLE, actions=[u'OUTPUT:IN_PORT'])
        self.wait_nonzero_packet_count_flow(
            {u'in_port': self.port_map['port_1'], u'dl_dst': macvlan2_mac},
            table_id=self._ETH_DST_TABLE, actions=[u'OUTPUT:IN_PORT'])


class FaucetUntaggedGroupHairpinTest(FaucetUntaggedHairpinTest):

    CONFIG = """
        group_table: True
        interfaces:
            %(port_1)d:
                hairpin: True
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
    """


class FaucetUntaggedTcpIPv4IperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        first_host_ip = ipaddress.ip_address(unicode(first_host.IP())) # pytype: disable=name-error
        second_host_ip = ipaddress.ip_address(unicode(second_host.IP())) # pytype: disable=name-error
        for _ in range(3):
            self.ping_all_when_learned()
            self.one_ipv4_ping(first_host, second_host_ip)
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                1, first_host_ip, second_host_ip)
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
                1, first_host_ip.ip, second_host_ip.ip)
            self.flap_all_switch_ports()


class FaucetSanityTest(FaucetUntaggedTest):
    """Sanity test - make sure test environment is correct before running all tess."""

    def verify_dp_port_healthy(self, dp_port, retries=5, min_mbps=100):
        for _ in range(retries):
            port_desc = self.get_port_desc_from_dpid(self.dpid, dp_port)
            port_name = port_desc['name']
            port_state = port_desc['state']
            port_config = port_desc['config']
            port_speed_mbps = (port_desc['curr_speed'] * 1e3) / 1e6
            error('DP %u is %s, at %u mbps\n' % (dp_port, port_name, port_speed_mbps))
            if port_speed_mbps < min_mbps:
                error('port speed %u below minimum %u mbps\n' % (
                    port_speed_mbps, min_mbps))
            elif port_config != 0:
                error('port config %u must be 0 (all clear)' % port_config)
            elif not (port_state == 0 or port_state == 4):
                error('state %u must be 0 (all flags clear or live)\n' % (
                    port_state))
            else:
                return
            time.sleep(1)
        self.fail('DP port %u not healthy (%s)' % (dp_port, port_desc))

    def test_portmap(self):
        prom_desc = self.scrape_prometheus(
            controller='faucet', var='of_dp_desc_stats')
        self.assertIsNotNone(prom_desc, msg='Cannot scrape of_dp_desc_stats')
        error('DP: %s\n' % prom_desc[0])
        for i, host in enumerate(self.net.hosts):
            in_port = 'port_%u' % (i + 1)
            dp_port = self.port_map[in_port]
            if in_port in self.switch_map:
                error('verifying cabling for %s: host %s -> dp %u\n' % (
                    in_port, self.switch_map[in_port], dp_port))
            else:
                error('verifying host %s -> dp %s\n' % (
                    in_port, dp_port))
            self.verify_dp_port_healthy(dp_port)
            self.require_host_learned(host, in_port=dp_port)

    def test_listening(self):
        msg_template = (
            'Processes listening on test, or all interfaces may interfere with tests. '
            'Please deconfigure them (e.g. configure interface as "unmanaged"):\n\n%s')
        controller = self._get_controller()
        ss_out = controller.cmd('ss -lnep').splitlines()
        listening_all_re = re.compile(r'^.+\s+(\*:\d+|:::\d+)\s+(:+\*|\*:\*).+$')
        listening_all = [line for line in ss_out if listening_all_re.match(line)]
        for test_intf in list(self.switch_map.values()):
            int_re = re.compile(r'^.+\b%s\b.+$' % test_intf)
            listening_int = [line for line in ss_out if int_re.match(line)]
            self.assertFalse(
                len(listening_int),
                msg=(msg_template % '\n'.join(listening_int)))
        if listening_all:
            print('Warning: %s' % (msg_template % '\n'.join(listening_all)))


class FaucetUntaggedPrometheusGaugeTest(FaucetUntaggedTest):
    """Testing Gauge Prometheus"""

    GAUGE_CONFIG_DBS = """
    prometheus:
        type: 'prometheus'
        prometheus_addr: '::1'
        prometheus_port: %(gauge_prom_port)d
"""
    config_ports = {'gauge_prom_port': None}

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['%s']
        type: 'port_stats'
        interval: 5
        db: 'prometheus'
    port_state:
        dps: ['%s']
        type: 'port_state'
        interval: 5
        db: 'prometheus'
    flow_table:
        dps: ['%s']
        type: 'flow_table'
        interval: 5
        db: 'prometheus'
""" % (self.DP_NAME, self.DP_NAME, self.DP_NAME)

    def _start_gauge_check(self):
        if not self.gauge_controller.listen_port(self.config_ports['gauge_prom_port']):
            return 'gauge not listening on prometheus port'
        return None

    def scrape_port_counters(self, port, port_vars):
        port_counters = {}
        port_labels = {
            'dp_id': self.dpid,
            'dp_name': self.DP_NAME,
            'port_name': self.port_map['port_%u' % port],
        }
        for port_var in port_vars:
            val = self.scrape_prometheus_var(
                port_var, labels=port_labels, controller='gauge', retries=3)
            self.assertIsNotNone(val, '%s missing for port %u' % (port_var, port))
            port_counters[port_var] = val
            for port_state_var in ('of_port_state', 'of_port_reason'):
                self.assertTrue(val and val > 0, self.scrape_prometheus_var(
                    port_state_var, labels=port_labels, controller='gauge', retries=3))
        return port_counters

    def _prom_ports_updating(self):
        port_vars = (
            'of_port_rx_bytes',
            'of_port_tx_bytes',
            'of_port_rx_packets',
            'of_port_tx_packets',
        )
        self.flap_all_switch_ports()
        first_port_counters = {}
        for i, _ in enumerate(self.net.hosts):
            port = i + 1
            port_counters = self.scrape_port_counters(port, port_vars)
            first_port_counters[port] = port_counters
        counter_delay = 0

        for _ in range(self.DB_TIMEOUT * 3):
            self.ping_all_when_learned()
            updating = True
            for i, _ in enumerate(self.net.hosts):
                port = i + 1
                port_counters = self.scrape_port_counters(port, port_vars)
                for port_var, val in list(port_counters.items()):
                    if not val > first_port_counters[port][port_var]:
                        updating = False
                        break
                if not updating:
                    break
            counter_delay += 1
            time.sleep(1)

        error('counter latency approx %u sec\n' % counter_delay)
        return updating

    def test_untagged(self):
        self.wait_dp_status(1, controller='gauge')
        self.assertIsNotNone(self.scrape_prometheus_var(
            'faucet_pbr_version', any_labels=True, controller='gauge', retries=3))
        conf = self._get_conf()
        cookie = conf['dps'][self.DP_NAME]['cookie']

        if not self._prom_ports_updating():
            self.fail(msg='Gauge Prometheus port counters not increasing')

        for _ in range(self.DB_TIMEOUT * 3):
            updated_counters = True
            for host in self.net.hosts:
                host_labels = {
                    'dp_id': self.dpid,
                    'dp_name': self.DP_NAME,
                    'cookie': cookie,
                    'eth_dst': host.MAC(),
                    'inst_count': str(1),
                    'priority': str(9099),
                    'table_id': str(self._ETH_DST_TABLE),
                    'vlan': str(100),
                    'vlan_vid': str(4196)
                }
                packet_count = self.scrape_prometheus_var(
                    'flow_packet_count_eth_dst', labels=host_labels, controller='gauge')
                byte_count = self.scrape_prometheus_var(
                    'flow_byte_count_eth_dst', labels=host_labels, controller='gauge')
                if packet_count is None or packet_count == 0:
                    updated_counters = False
                if byte_count is None or byte_count == 0:
                    updated_counters = False
            if updated_counters:
                return
            time.sleep(1)

        self.fail(msg='Gauge Prometheus flow counters not increasing')


class FaucetUntaggedInfluxTest(FaucetUntaggedTest):
    """Basic untagged VLAN test with Influx."""

    GAUGE_CONFIG_DBS = """
    influx:
        type: 'influx'
        influx_db: 'faucet'
        influx_host: '127.0.0.1'
        influx_port: %(gauge_influx_port)d
        influx_user: 'faucet'
        influx_pwd: ''
        influx_retries: 1
""" + """
        influx_timeout: %u
""" % FaucetUntaggedTest.DB_TIMEOUT
    config_ports = {'gauge_influx_port': None}
    influx_log = None
    server_thread = None
    server = None

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['%s']
        type: 'port_stats'
        interval: 2
        db: 'influx'
    port_state:
        dps: ['%s']
        type: 'port_state'
        interval: 2
        db: 'influx'
    flow_table:
        dps: ['%s']
        type: 'flow_table'
        interval: 2
        db: 'influx'
""" % (self.DP_NAME, self.DP_NAME, self.DP_NAME)

    def setup_influx(self):
        self.influx_log = os.path.join(self.tmpdir, 'influx.log')
        if self.server:
            self.server.influx_log = self.influx_log
            self.server.timeout = self.DB_TIMEOUT

    def setUp(self): # pylint: disable=invalid-name
        self.handler = InfluxPostHandler
        super(FaucetUntaggedInfluxTest, self).setUp()
        self.setup_influx()

    def tearDown(self): # pylint: disable=invalid-name
        if self.server:
            self.server.shutdown()
            self.server.socket.close()
        super(FaucetUntaggedInfluxTest, self).tearDown()

    def _wait_error_shipping(self, timeout=None):
        if timeout is None:
            timeout = self.DB_TIMEOUT * 3 * 2
        gauge_log_name = self.env['gauge']['GAUGE_LOG']
        for _ in range(timeout):
            if self.matching_lines_from_file(r'.+error shipping.+', gauge_log_name):
                return
            time.sleep(1)
        self.fail('Influx error not noted in %s' % gauge_log_name)

    def _verify_influx_log(self):
        self.assertTrue(os.path.exists(self.influx_log))
        observed_vars = set()
        with open(self.influx_log) as influx_log:
            influx_log_lines = influx_log.readlines()
        for point_line in influx_log_lines:
            point_fields = point_line.strip().split()
            self.assertEqual(3, len(point_fields), msg=point_fields)
            ts_name, value_field, _ = point_fields
            value = float(value_field.split('=')[1])
            ts_name_fields = ts_name.split(',')
            self.assertGreater(len(ts_name_fields), 1)
            observed_vars.add(ts_name_fields[0])
            label_values = {}
            for label_value in ts_name_fields[1:]:
                label, value = label_value.split('=')
                label_values[label] = value
            if ts_name.startswith('flow'):
                self.assertTrue('inst_count' in label_values, msg=point_line)
                if 'vlan_vid' in label_values:
                    self.assertEqual(
                        int(label_values['vlan']), int(value) ^ 0x1000)
        self.verify_no_exception(self.env['gauge']['GAUGE_EXCEPTION_LOG'])
        self.assertEqual(set([
            'dropped_in', 'dropped_out', 'bytes_out', 'flow_packet_count',
            'errors_in', 'bytes_in', 'flow_byte_count', 'port_state_reason',
            'packets_in', 'packets_out']), observed_vars)

    def _wait_influx_log(self):
        for _ in range(self.DB_TIMEOUT * 3):
            if os.path.exists(self.influx_log):
                return
            time.sleep(1)
        return

    def _start_gauge_check(self):
        influx_port = self.config_ports['gauge_influx_port']
        try:
            self.server = QuietHTTPServer(
                (mininet_test_util.LOCALHOST, influx_port), self.handler)
            self.server.timeout = self.DB_TIMEOUT
            self.server_thread = threading.Thread(
                target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            return None
        except socket.error as err:
            return 'cannot start Influx test server: %s' % err

    def test_untagged(self):
        self.ping_all_when_learned()
        self.hup_gauge()
        self.flap_all_switch_ports()
        self._wait_influx_log()
        self._verify_influx_log()


class FaucetUntaggedMultiDBWatcherTest(
        FaucetUntaggedInfluxTest, FaucetUntaggedPrometheusGaugeTest):
    GAUGE_CONFIG_DBS = """
    prometheus:
        type: 'prometheus'
        prometheus_addr: '::1'
        prometheus_port: %(gauge_prom_port)d
    influx:
        type: 'influx'
        influx_db: 'faucet'
        influx_host: '127.0.0.1'
        influx_port: %(gauge_influx_port)d
        influx_user: 'faucet'
        influx_pwd: ''
        influx_retries: 1
""" + """
        influx_timeout: %u
""" % FaucetUntaggedTest.DB_TIMEOUT
    config_ports = {
        'gauge_prom_port': None,
        'gauge_influx_port': None}

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['%s']
        type: 'port_stats'
        interval: 5
        dbs: ['prometheus', 'influx']
    port_state:
        dps: ['%s']
        type: 'port_state'
        interval: 5
        dbs: ['prometheus', 'influx']
    flow_table:
        dps: ['%s']
        type: 'flow_table'
        interval: 5
        dbs: ['prometheus', 'influx']
""" % (self.DP_NAME, self.DP_NAME, self.DP_NAME)

    def test_untagged(self):
        self.wait_dp_status(1, controller='gauge')
        self._prom_ports_updating()
        self.ping_all_when_learned()
        self.hup_gauge()
        self.flap_all_switch_ports()
        self._wait_influx_log()
        self._verify_influx_log()


class FaucetUntaggedInfluxDownTest(FaucetUntaggedInfluxTest):

    def _start_gauge_check(self):
        return None

    def test_untagged(self):
        self.ping_all_when_learned()
        self._wait_error_shipping()
        self.verify_no_exception(self.env['gauge']['GAUGE_EXCEPTION_LOG'])


class FaucetUntaggedInfluxUnreachableTest(FaucetUntaggedInfluxTest):

    GAUGE_CONFIG_DBS = """
    influx:
        type: 'influx'
        influx_db: 'faucet'
        influx_host: '127.0.0.2'
        influx_port: %(gauge_influx_port)d
        influx_user: 'faucet'
        influx_pwd: ''
        influx_timeout: 2
"""

    def _start_gauge_check(self):
        return None

    def test_untagged(self):
        self.gauge_controller.cmd(
            'route add 127.0.0.2 gw 127.0.0.1 lo')
        self.ping_all_when_learned()
        self._wait_error_shipping()
        self.verify_no_exception(self.env['gauge']['GAUGE_EXCEPTION_LOG'])


class FaucetSingleUntaggedInfluxTooSlowTest(FaucetUntaggedInfluxTest):

    def setUp(self): # pylint: disable=invalid-name
        self.handler = SlowInfluxPostHandler
        super(FaucetUntaggedInfluxTest, self).setUp()
        self.setup_influx()

    def test_untagged(self):
        self.ping_all_when_learned()
        self._wait_influx_log()
        self.assertTrue(os.path.exists(self.influx_log))
        self._wait_error_shipping()
        self.verify_no_exception(self.env['gauge']['GAUGE_EXCEPTION_LOG'])


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
        first_host.setMAC('0e:00:00:00:01:01')
        second_host.setMAC('0e:00:00:00:02:02')
        self.one_ipv4_ping(
            first_host, second_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            second_host, first_host.IP(), require_host_learned=False)


class FaucetNailedFailoverForwardingTest(FaucetNailedForwardingTest):

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
                    failover:
                        group_id: 1001
                        ports: [b2, b3]
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    failover:
                        group_id: 1002
                        ports: [b2, b3]
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
    4:
        - rule:
            actions:
                allow: 0
"""

    def test_untagged(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        first_host.setMAC('0e:00:00:00:01:01')
        second_host.setMAC('0e:00:00:00:02:02')
        third_host.setMAC('0e:00:00:00:02:02')
        third_host.setIP(second_host.IP())
        self.one_ipv4_ping(
            first_host, second_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            second_host, first_host.IP(), require_host_learned=False)
        self.set_port_down(self.port_map['port_2'])
        self.one_ipv4_ping(
            first_host, third_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            third_host, first_host.IP(), require_host_learned=False)


class FaucetUntaggedLLDPBlockedTest(FaucetUntaggedTest):

    def test_untagged(self):
        self.ping_all_when_learned()
        self.assertTrue(self.verify_lldp_blocked())
        # Verify 802.1x flood block triggered.
        self.wait_nonzero_packet_count_flow(
            {u'dl_dst': u'01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0'},
            table_id=self._FLOOD_TABLE)


class FaucetUntaggedCDPTest(FaucetUntaggedTest):

    def test_untagged(self):
        self.ping_all_when_learned()
        self.assertFalse(self.is_cdp_blocked())


class FaucetZodiacUntaggedTest(FaucetUntaggedTest):
    """Zodiac has only 3 ports available, and one controller so no Gauge."""

    RUN_GAUGE = False
    N_UNTAGGED = 3

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


class FaucetTaggedAndUntaggedSameVlanTest(FaucetTest):
    """Test mixture of tagged and untagged hosts on the same VLAN."""

    N_TAGGED = 1
    N_UNTAGGED = 3
    LINKS_PER_HOST = 1
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

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetTaggedAndUntaggedSameVlanTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=1, n_untagged=3, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_untagged(self):
        """Test connectivity including after port flapping."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()
        self.verify_broadcast()
        # test tagged and untagged hosts
        for host in self.net.hosts[:2]:
            self.verify_no_bcast_to_self(host)


class FaucetTaggedAndUntaggedSameVlanGroupTest(FaucetTaggedAndUntaggedSameVlanTest):

    CONFIG = """
        group_table: True
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


class FaucetZodiacTaggedAndUntaggedSameVlanTest(FaucetUntaggedTest):

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
        self.assertEqual(2, len(learned_hosts))
        self.assertEqual(2, self.scrape_prometheus_var(
            'vlan_hosts_learned', {'vlan': '100'}))
        self.assertGreater(
            self.scrape_prometheus_var(
                'vlan_learn_bans', {'vlan': '100'}), 0)


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
            self.add_macvlan(second_host, mac_intf, ipa=mac_ipv4)
            second_host.cmd('ping -c1 -I%s %s > /dev/null &' % (mac_intf, first_host.IP()))
        flows = self.get_matching_flows_on_dpid(
            self.dpid,
            {u'dl_vlan': u'100', u'in_port': int(self.port_map['port_2'])},
            table_id=self._ETH_SRC_TABLE)
        self.assertEqual(self.MAX_HOSTS, len(flows))
        self.assertGreater(
            self.scrape_prometheus_var(
                'port_learn_bans', {'port': self.port_map['port_2']}), 0)
        learned_macs = [
            mac for _, mac in self.scrape_prometheus_var(
                'learned_macs',
                {'port': self.port_map['port_2'], 'vlan': '100'},
                multiple=True) if mac]
        self.assertEqual(self.MAX_HOSTS, len(learned_macs))


class FaucetSingleHostsTimeoutPrometheusTest(FaucetUntaggedTest):
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
        arp_neighbor_timeout: 10
        ignore_learn_ins: 0
        learn_jitter: 0
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

    def hosts_learned(self, hosts):
        """Check that hosts are learned by FAUCET on the expected ports."""
        macs_learned = []
        for mac, port in hosts.items():
            if self.prom_mac_learned(mac, port=port):
                self.mac_learned(mac, in_port=port)
                macs_learned.append(mac)
        return macs_learned

    def verify_hosts_learned(self, first_host, second_host, mac_ips, hosts):
        for _ in range(3):
            fping_out = first_host.cmd(mininet_test_util.timeout_cmd(
                'fping -i300 -c3 %s' % ' '.join(mac_ips), 5))
            macs_learned = self.hosts_learned(hosts)
            if len(macs_learned) == len(hosts):
                return
            time.sleep(1)
        first_host_diag = first_host.cmd('ifconfig -a ; arp -an')
        second_host_diag = second_host.cmd('ifconfig -a ; arp -an')
        self.fail('%s cannot be learned (%s != %s)\nfirst host %s\nsecond host %s\n' % (
            mac_ips, macs_learned, fping_out, first_host_diag, second_host_diag))

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        all_learned_mac_ports = {}

        # learn batches of hosts, then down them
        for base in (10, 20, 30):
            def add_macvlans(base, count):
                mac_intfs = []
                mac_ips = []
                learned_mac_ports = {}
                for i in range(base, base + count):
                    mac_intf = 'mac%u' % i
                    mac_intfs.append(mac_intf)
                    mac_ipv4 = '10.0.0.%u' % i
                    mac_ips.append(mac_ipv4)
                    self.add_macvlan(second_host, mac_intf, ipa=mac_ipv4)
                    macvlan_mac = self.get_mac_of_intf(second_host, mac_intf)
                    learned_mac_ports[macvlan_mac] = self.port_map['port_2']
                return (mac_intfs, mac_ips, learned_mac_ports)

            def down_macvlans(macvlans):
                for macvlan in macvlans:
                    second_host.cmd('ip link set dev %s down' % macvlan)

            def learn_then_down_hosts(base, count):
                mac_intfs, mac_ips, learned_mac_ports = add_macvlans(base, count)
                self.verify_hosts_learned(first_host, second_host, mac_ips, learned_mac_ports)
                down_macvlans(mac_intfs)
                return learned_mac_ports

            learned_mac_ports = learn_then_down_hosts(base, 5)
            all_learned_mac_ports.update(learned_mac_ports)

        # make sure at least one host still learned
        learned_macs = self.hosts_learned(all_learned_mac_ports)
        self.assertTrue(learned_macs)

        # make sure they all eventually expire
        for _ in range(self.TIMEOUT * 2):
            learned_macs = self.hosts_learned(all_learned_mac_ports)
            self.verify_learn_counters(
                100, list(range(1, len(self.net.hosts) + 1)))
            if not learned_macs:
                return
            time.sleep(1)

        self.fail('MACs did not expire: %s' % learned_macs)


class FaucetSingleL3LearnMACsOnPortTest(FaucetUntaggedTest):

    TEST_IPV4_NET = u'10.0.0.0'
    TEST_IPV4_PREFIX = 16 # must hold more than MAX_HOSTS + 4
    LEARN_IPV4 = u'10.0.254.254'
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        # Must be > than MAX_HOSTS + 4
        max_hosts: 2052
        faucet_vips: ["10.0.254.254/16"]
"""

    CONFIG = """
        ignore_learn_ins: 0
        metrics_rate_limit_sec: 3
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                max_hosts: 1024
            %(port_2)d:
                native_vlan: 100
                description: "b2"
                max_hosts: 1024
            %(port_3)d:
                native_vlan: 100
                description: "b3"
                max_hosts: 1024
            %(port_4)d:
                native_vlan: 100
                description: "b4"
                max_hosts: 1024
"""

    def test_untagged(self):
        test_net = ipaddress.IPv4Network(
            u'%s/%s' % (self.TEST_IPV4_NET, self.TEST_IPV4_PREFIX))
        learn_ip = ipaddress.IPv4Address(self.LEARN_IPV4)
        self.verify_learning(test_net, learn_ip, 64, 2048)


class FaucetSingleL2LearnMACsOnPortTest(FaucetUntaggedTest):

    TEST_IPV4_NET = u'10.0.0.0'
    TEST_IPV4_PREFIX = 16 # must hold more than MAX_HOSTS + 4
    LEARN_IPV4 = u'10.0.0.1'
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        # Must be > than MAX_HOSTS + 4
        max_hosts: 5000
"""

    CONFIG = """
        ignore_learn_ins: 0
        metrics_rate_limit_sec: 3
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                max_hosts: 2048
            %(port_2)d:
                native_vlan: 100
                description: "b2"
                max_hosts: 2048
            %(port_3)d:
                native_vlan: 100
                description: "b3"
                max_hosts: 2048
            %(port_4)d:
                native_vlan: 100
                description: "b4"
                max_hosts: 2048
"""

    def test_untagged(self):
        test_net = ipaddress.IPv4Network(
            u'%s/%s' % (self.TEST_IPV4_NET, self.TEST_IPV4_PREFIX))
        learn_ip = ipaddress.IPv4Address(self.LEARN_IPV4)
        self.verify_learning(test_net, learn_ip, 64, 4096)


class FaucetUntaggedHUPTest(FaucetUntaggedTest):
    """Test handling HUP signal without config change."""

    def _configure_count_with_retry(self, expected_count):
        for _ in range(3):
            configure_count = self.get_configure_count()
            if configure_count == expected_count:
                return
            time.sleep(1)
        self.fail('configure count %u != expected %u' % (
            configure_count, expected_count))

    def test_untagged(self):
        """Test that FAUCET receives HUP signal and keeps switching."""
        init_config_count = self.get_configure_count()
        reload_type_vars = (
            'faucet_config_reload_cold',
            'faucet_config_reload_warm')
        reload_vals = {}
        for var in reload_type_vars:
            reload_vals[var] = self.scrape_prometheus_var(
                var, dpid=True, default=None)
        for i in range(init_config_count, init_config_count+3):
            self._configure_count_with_retry(i)
            with open(self.faucet_config_path, 'a') as config_file:
                config_file.write('\n')
            self.verify_faucet_reconf(change_expected=False)
            self._configure_count_with_retry(i+1)
            self.assertEqual(
                self.scrape_prometheus_var(
                    'of_dp_disconnections', dpid=True, default=None),
                0)
            self.assertEqual(
                self.scrape_prometheus_var(
                    'of_dp_connections', dpid=True, default=None),
                1)
            self.wait_until_controller_flow()
            self.ping_all_when_learned()
        for var in reload_type_vars:
            self.assertEqual(
                reload_vals[var],
                self.scrape_prometheus_var(var, dpid=True, default=None))


class FaucetIPv4TupleTest(FaucetTest):

    MAX_RULES = 1024
    ETH_TYPE = 0x0800
    NET_BASE = ipaddress.IPv4Network(u'10.0.0.0/16')
    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
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
                acl_in: 1
"""
    START_ACL_CONFIG = """
acls:
  1:
    exact_match: true
    rules:
    - rule:
        actions: {allow: 1}
        eth_type: 2048
        ip_proto: 6
        ipv4_dst: 127.0.0.1
        ipv4_src: 127.0.0.1
        tcp_dst: 65535
        tcp_src: 65535
"""

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetIPv4TupleTest, self).setUp()
        self.acl_config_file = os.path.join(self.tmpdir, 'acl.txt')
        self.CONFIG = '\n'.join(
            (self.CONFIG, 'include:\n     - %s' % self.acl_config_file))
        open(self.acl_config_file, 'w').write(self.START_ACL_CONFIG)
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def _push_tuples(self, eth_type, host_ips):
        max_rules = len(host_ips)
        rules = 1
        while rules <= max_rules:
            rules_yaml = []
            for rule in range(rules):
                host_ip = host_ips[rule]
                port = (rule + 1) % 2**16
                ip_match = str(host_ip)
                rule_yaml = {
                    'eth_type': eth_type,
                    'ip_proto': 6,
                    'tcp_src': port,
                    'tcp_dst': port,
                    'ipv%u_src' % host_ip.version: ip_match,
                    'ipv%u_dst' % host_ip.version: ip_match,
                    'actions': {'allow': 1},
                }
                rules_yaml.append({'rule': rule_yaml})
            yaml_acl_conf = {'acls': {1: {'exact_match': True, 'rules': rules_yaml}}}
            tuple_txt = '%u IPv%u tuples\n' % (len(rules_yaml), host_ip.version)
            error('pushing %s' % tuple_txt)
            self.reload_conf(
                yaml_acl_conf, self.acl_config_file,
                restart=True, cold_start=False)
            error('pushed %s' % tuple_txt)
            self.wait_until_matching_flow({'tp_src': port}, table_id=0)
            rules *= 2

    def test_tuples(self):
        host_ips = [host_ip for host_ip in itertools.islice(
            self.NET_BASE.hosts(), self.MAX_RULES)]
        self._push_tuples(self.ETH_TYPE, host_ips)


class FaucetIPv6TupleTest(FaucetIPv4TupleTest):

    MAX_RULES = 1024
    ETH_TYPE = 0x86DD
    NET_BASE = ipaddress.IPv6Network(u'fc00::00/64')
    START_ACL_CONFIG = """
acls:
  1:
    exact_match: true
    rules:
    - rule:
        actions: {allow: 1}
        eth_type: 34525
        ip_proto: 6
        ipv6_dst: ::1
        ipv6_src: ::1
        tcp_dst: 65535
        tcp_src: 65535
"""


class FaucetConfigReloadTestBase(FaucetTest):
    """Test handling HUP signal with config change."""

    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
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
                acl_in: allow
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
                tagged_vlans: [200]
"""
    ACL = """
acls:
    1:
        - rule:
            description: "rule 1"
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 1
        - rule:
            cookie: COOKIE
            actions:
                allow: 1
    2:
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 1
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 0
        - rule:
            cookie: COOKIE
            actions:
                allow: 1
    3:
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5003
            actions:
                allow: 0
    4:
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 1
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
    deny:
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 65535
            actions:
                allow: 0
        - rule:
            cookie: COOKIE
            actions:
                allow: 0
    allow:
        - rule:
            cookie: COOKIE
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 65535
            actions:
                allow: 1
        - rule:
            cookie: COOKIE
            actions:
                allow: 1
"""
    ACL_COOKIE = None

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetConfigReloadTestBase, self).setUp()
        self.ACL_COOKIE = random.randint(1, 2**16-1)
        self.ACL = self.ACL.replace('COOKIE', str(self.ACL_COOKIE))
        self.acl_config_file = '%s/acl.yaml' % self.tmpdir
        with open(self.acl_config_file, 'w') as config_file:
            config_file.write(self.ACL)
        self.CONFIG = '\n'.join(
            (self.CONFIG, 'include:\n     - %s' % self.acl_config_file))
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()


class FaucetConfigReloadTest(FaucetConfigReloadTestBase):

    def test_add_unknown_dp(self):
        conf = self._get_conf()
        conf['dps']['unknown'] = {
            'dp_id': int(self.rand_dpid()),
            'hardware': 'Open vSwitch',
        }
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=False)

    def test_tabs_are_bad(self):
        self.ping_all_when_learned()
        orig_conf = self._get_conf()
        self.force_faucet_reload(
            '\t'.join(('tabs', 'are', 'bad')))
        self.ping_all_when_learned()
        self.reload_conf(
            orig_conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=False)

    def test_port_change_vlan(self):
        first_host, second_host = self.net.hosts[:2]
        third_host, fourth_host = self.net.hosts[2:]
        self.ping_all_when_learned()
        self.change_port_config(
            self.port_map['port_1'], 'native_vlan', 200,
            restart=False, cold_start=False)
        self.change_port_config(
            self.port_map['port_2'], 'native_vlan', 200,
            restart=True, cold_start=True)
        for port_name in ('port_1', 'port_2'):
            self.wait_until_matching_flow(
                {u'in_port': int(self.port_map[port_name])},
                table_id=self._VLAN_TABLE,
                actions=[u'SET_FIELD: {vlan_vid:4296}'])
        self.one_ipv4_ping(first_host, second_host.IP(), require_host_learned=False)
        # hosts 1 and 2 now in VLAN 200, so they shouldn't see floods for 3 and 4.
        self.verify_vlan_flood_limited(
            third_host, fourth_host, first_host)

    def test_port_change_acl(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        orig_conf = self._get_conf()
        self.change_port_config(
            self.port_map['port_1'], 'acl_in', 1,
            cold_start=False)
        self.wait_until_matching_flow(
            {u'in_port': int(self.port_map['port_1']),
             u'eth_type': 0x800, u'tcp_dst': 5001, u'ip_proto': 6},
            table_id=self._PORT_ACL_TABLE, cookie=self.ACL_COOKIE)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)
        self.reload_conf(
            orig_conf, self.faucet_config_path,
            restart=True, cold_start=False, host_cache=100)
        self.verify_tp_dst_notblocked(
            5001, first_host, second_host, table_id=None)
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=None)

    def test_port_change_perm_learn(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        self.change_port_config(
            self.port_map['port_1'], 'permanent_learn', True,
            restart=True, cold_start=False)
        self.ping_all_when_learned(hard_timeout=0)
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.retry_net_ping(hosts=(first_host, second_host))
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned(hard_timeout=0)
        self.change_port_config(
            self.port_map['port_1'], 'acl_in', 1,
            restart=True, cold_start=False)
        self.wait_until_matching_flow(
            {u'in_port': int(self.port_map['port_1']), u'tcp_dst': 5001, u'ip_proto': 6},
            table_id=self._PORT_ACL_TABLE)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetDeleteConfigReloadTest(FaucetConfigReloadTestBase):

    def test_delete_interface(self):
        # With all ports changed, we should cold start.
        conf = self._get_conf()
        del conf['dps'][self.DP_NAME]['interfaces']
        conf['dps'][self.DP_NAME]['interfaces'] = {
            int(self.port_map['port_1']): {
                'native_vlan': '100',
                'tagged_vlans': ['200'],
            }
        }
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True)


class FaucetRouterConfigReloadTest(FaucetConfigReloadTestBase):

    def test_router_config_reload(self):
        conf = self._get_conf()
        conf['routers'] = {
            'router-1': {
                'vlans': ['100', '200'],
            }
        }
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True)


class FaucetConfigReloadAclTest(FaucetConfigReloadTestBase):

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
                acls_in: [allow]
            %(port_2)d:
                native_vlan: 100
                description: "b2"
                acl_in: allow
            %(port_3)d:
                native_vlan: 100
                description: "b3"
                acl_in: deny
            %(port_4)d:
                native_vlan: 100
                description: "b4"
                acl_in: deny
"""

    def _verify_hosts_learned(self, hosts):
        self.net.pingAll()
        for host in hosts:
            self.require_host_learned(host)
        self.assertEqual(len(hosts), self.scrape_prometheus_var(
            'vlan_hosts_learned', {'vlan': '100'}))

    def test_port_acls(self):
        hup = not self.STAT_RELOAD
        first_host, second_host, third_host = self.net.hosts[:3]
        self._verify_hosts_learned((first_host, second_host))
        self.change_port_config(
            self.port_map['port_3'], 'acl_in', 'allow',
            restart=True, cold_start=False, hup=hup)
        self.change_port_config(
            self.port_map['port_1'], 'acls_in', [3, 4, 'allow'],
            restart=True, cold_start=False, hup=hup)
        self.coldstart_conf(hup=hup)
        self._verify_hosts_learned((first_host, second_host, third_host))
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)
        self.verify_tp_dst_blocked(5003, first_host, second_host)


class FaucetConfigStatReloadAclTest(FaucetConfigReloadAclTest):

    # Use the stat-based reload method.
    STAT_RELOAD = '1'


class FaucetUntaggedBGPDualstackDefaultRouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import default route from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24", "fc00::1:254/112"]
        bgp_port: %(bgp_port)d
        bgp_server_addresses: ["127.0.0.1", "::1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1", "::1"]
        bgp_connect_mode: "passive"
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_peer_conf = """
    static {
      route 0.0.0.0/0 next-hop 10.0.0.1 local-preference 100;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        first_host, second_host = self.net.hosts[:2]
        first_host_alias_ip = ipaddress.ip_interface(u'10.99.99.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV4.ip)
        for _ in range(2):
            self.one_ipv4_ping(second_host, first_host_alias_ip.ip)
            self.one_ipv4_controller_ping(first_host)
            self.coldstart_conf()


class FaucetUntaggedBGPIPv4DefaultRouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import default route from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: %(bgp_port)d
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_connect_mode: "passive"
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_peer_conf = """
    static {
      route 0.0.0.0/0 next-hop 10.0.0.1 local-preference 100;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        first_host, second_host = self.net.hosts[:2]
        first_host_alias_ip = ipaddress.ip_interface(u'10.99.99.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV4.ip)
        self.one_ipv4_ping(second_host, first_host_alias_ip.ip)
        self.one_ipv4_controller_ping(first_host)
        self.coldstart_conf()


class FaucetUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import from BGP."""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        bgp_port: %(bgp_port)d
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_connect_mode: "passive"
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_peer_conf = """
    static {
      route 10.0.1.0/24 next-hop 10.0.0.1 local-preference 100;
      route 10.0.2.0/24 next-hop 10.0.0.2 local-preference 100;
      route 10.0.3.0/24 next-hop 10.0.0.2 local-preference 100;
      route 10.0.4.0/24 next-hop 10.0.0.254;
      route 10.0.5.0/24 next-hop 10.10.0.1;
   }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        first_host, second_host = self.net.hosts[:2]
        # wait until 10.0.0.1 has been resolved
        self.wait_for_route_as_flow(
            first_host.MAC(), ipaddress.IPv4Network(u'10.99.99.0/24'))
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route(r'.+10.0.4.0\/24 cannot be us$')
        self.verify_invalid_bgp_route(r'.+10.0.5.0\/24 is not a connected network$')
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
        bgp_server_addresses: ["127.0.0.1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["127.0.0.1"]
        bgp_connect_mode: "passive"
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
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf(mininet_test_util.LOCALHOST)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes sent."""
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        # exabgp should have received our BGP updates
        updates = self.exabgp_updates(self.exabgp_log)
        self.assertTrue(re.search('10.0.0.0/24 next-hop 10.0.0.254', updates))
        self.assertTrue(re.search('10.0.1.0/24 next-hop 10.0.0.1', updates))
        self.assertTrue(re.search('10.0.2.0/24 next-hop 10.0.0.2', updates))
        self.assertTrue(re.search('10.0.2.0/24 next-hop 10.0.0.2', updates))


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
        self.assertFalse(self.bogus_mac_flooded_to_port1())


class FaucetUntaggedHostMoveTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.net.hosts[0:2]
        self.retry_net_ping(hosts=(first_host, second_host))
        self.swap_host_macs(first_host, second_host)
        self.net.ping((first_host, second_host))
        for host, in_port in (
                (first_host, self.port_map['port_1']),
                (second_host, self.port_map['port_2'])):
            self.require_host_learned(host, in_port=in_port)
        self.retry_net_ping(hosts=(first_host, second_host))


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
        self.ping_all_when_learned(hard_timeout=0)
        first_host, second_host, third_host = self.net.hosts[0:3]
        # 3rd host impersonates 1st, 3rd host breaks but 1st host still OK
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.net.ping((second_host, third_host)))
        self.retry_net_ping(hosts=(first_host, second_host))
        # 3rd host stops impersonating, now everything fine again.
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned(hard_timeout=0)


class FaucetUntaggedLoopTest(FaucetTest):

    NUM_DPS = 1
    N_TAGGED = 0
    N_UNTAGGED = 2
    LINKS_PER_HOST = 2

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
                description: "b1"
            %(port_3)d:
                native_vlan: 100
                description: "b2"
                loop_protect: True
            %(port_4)d:
                native_vlan: 100
                description: "b2"
                loop_protect: True
"""

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetUntaggedLoopTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def total_port_bans(self):
        total_bans = 0
        for i in range(self.LINKS_PER_HOST * self.N_UNTAGGED):
            in_port = 'port_%u' % (i + 1)
            dp_port = self.port_map[in_port]
            total_bans += self.scrape_prometheus_var(
                'port_learn_bans', {'port': str(dp_port)}, dpid=True, default=0)
        return total_bans

    def test_untagged(self):
        first_host, second_host = self.net.hosts
        # Normal learning works
        self.one_ipv4_ping(first_host, second_host.IP())

        start_bans = self.total_port_bans()
        # Create a loop between interfaces on second host - a veth pair,
        # with two bridges, each connecting one leg of the pair to a host
        # interface.
        self.quiet_commands(second_host, (
            'ip link add name veth-loop1 type veth peer name veth-loop2',
            'ip link set veth-loop1 up',
            'ip link set veth-loop2 up',
            # TODO: tune for loop mitigation performance.
            'tc qdisc add dev veth-loop1 root tbf rate 1000kbps latency 10ms burst 1000',
            'tc qdisc add dev veth-loop2 root tbf rate 1000kbps latency 10ms burst 1000',
            # Connect one leg of veth pair to first host interface.
            'brctl addbr br-loop1',
            'brctl setfd br-loop1 0',
            'ip link set br-loop1 up',
            'brctl addif br-loop1 veth-loop1',
            'brctl addif br-loop1 %s-eth0' % second_host.name,
            # Connect other leg of veth pair.
            'brctl addbr br-loop2',
            'brctl setfd br-loop2 0',
            'ip link set br-loop2 up',
            'brctl addif br-loop2 veth-loop2',
            'brctl addif br-loop2 %s-eth1' % second_host.name))

        # Flood some traffic into the loop
        for _ in range(3):
            first_host.cmd('fping -i10 -c3 10.0.0.254')
            end_bans = self.total_port_bans()
            if end_bans > start_bans:
                return
            time.sleep(1)
        self.assertGreater(end_bans, start_bans)

        # Break the loop, and learning should work again
        self.quiet_commands(second_host, (
            'ip link set veth-loop1 down',
            'ip link set veth-loop2 down',))
        self.one_ipv4_ping(first_host, second_host.IP())


class FaucetUntaggedIPv4LACPTest(FaucetTest):

    NUM_DPS = 1
    N_TAGGED = 0
    N_UNTAGGED = 2
    LINKS_PER_HOST = 2

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
                lacp: 1
            %(port_2)d:
                native_vlan: 100
                description: "b1"
                lacp: 1
            %(port_3)d:
                native_vlan: 100
                description: "b2"
            %(port_4)d:
                native_vlan: 100
                description: "b2"
"""

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetUntaggedIPv4LACPTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        bond = 'bond0'
        # Linux driver should have this state (0x3f/63)
        #
        #    Actor State: 0x3f, LACP Activity, LACP Timeout, Aggregation, Synchronization, Collecting, Distributing
        #        .... ...1 = LACP Activity: Active
        #        .... ..1. = LACP Timeout: Short Timeout
        #        .... .1.. = Aggregation: Aggregatable
        #        .... 1... = Synchronization: In Sync
        #        ...1 .... = Collecting: Enabled
        #        ..1. .... = Distributing: Enabled
        #        .0.. .... = Defaulted: No
        #        0... .... = Expired: No
        #    [Actor State Flags: **DCSGSA]

        # FAUCET should have this state (0x3e/62)
        #    Actor State: 0x3e, LACP Timeout, Aggregation, Synchronization, Collecting, Distributing
        #        .... ...0 = LACP Activity: Passive
        #        .... ..1. = LACP Timeout: Short Timeout
        #        .... .1.. = Aggregation: Aggregatable
        #        .... 1... = Synchronization: In Sync
        #        ...1 .... = Collecting: Enabled
        #        ..1. .... = Distributing: Enabled
        #        .0.. .... = Defaulted: No
        #        0... .... = Expired: No
        #    [Actor State Flags: **DCSGS*]

        synced_state_txt = r"""
Slave Interface: \S+-eth0
MII Status: up
Speed: \d+ Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: \S+
Slave queue ID: 0
Aggregator ID: \d+
Actor Churn State: monitoring
Partner Churn State: monitoring
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:99
    port key: \d+
    port priority: 255
    port number: \d+
    port state: 63
details partner lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:01
    oper key: 1
    port priority: 255
    port number: %d
    port state: 62

Slave Interface: \S+-eth1
MII Status: up
Speed: \d+ Mbps
Duplex: full
Link Failure Count: 0
Permanent HW addr: \S+
Slave queue ID: 0
Aggregator ID: \d+
Actor Churn State: monitoring
Partner Churn State: monitoring
Actor Churned Count: 0
Partner Churned Count: 0
details actor lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:99
    port key: \d+
    port priority: 255
    port number: \d+
    port state: 63
details partner lacp pdu:
    system priority: 65535
    system mac address: 0e:00:00:00:00:01
    oper key: 1
    port priority: 255
    port number: %d
    port state: 62
""".strip() % (self.port_map['port_1'], self.port_map['port_2'])
        for lacp_port in (self.port_map['port_1'], self.port_map['port_2']):
            self.assertEqual(
                0,
                self.scrape_prometheus_var('port_lacp_status', {'port': str(lacp_port)}))
        orig_ip = first_host.IP()
        switch = self.net.switches[0]
        bond_members = [pair[0].name for pair in first_host.connectionsTo(switch)]
        # Deconfigure bond members
        for bond_member in bond_members:
            self.quiet_commands(first_host, (
                'ip link set %s down' % bond_member,
                'ip address flush dev %s' % bond_member))
        # Configure bond interface
        self.quiet_commands(first_host, (
            ('ip link add %s address 0e:00:00:00:00:99 '
             'type bond mode 802.3ad lacp_rate fast miimon 100') % bond,
            'ip add add %s/24 dev %s' % (orig_ip, bond),
            'ip link set %s up' % bond))
        # Add bond members
        for bond_member in bond_members:
            self.quiet_commands(first_host, (
                'ip link set dev %s master %s' % (bond_member, bond),))
        # LACP should come up and we can pass traffic.
        for _ in range(10):
            result = first_host.cmd('cat /proc/net/bonding/%s|sed "s/[ \t]*$//g"' % bond)
            result = '\n'.join([line.rstrip() for line in result.splitlines()])
            open(os.path.join(self.tmpdir, 'bonding-state.txt'), 'w').write(result)
            if re.search(synced_state_txt, result):
                self.one_ipv4_ping(first_host, '10.0.0.254', require_host_learned=False, intf=bond)
                return
            time.sleep(1)
        for lacp_port in (self.port_map['port_1'], self.port_map['port_2']):
            self.assertEqual(
                1,
                self.scrape_prometheus_var('port_lacp_status', {'port': str(lacp_port)}))
        self.fail('LACP did not synchronize: %s\n\nexpected:\n\n%s' % (
            result, synced_state_txt))
        self.one_ipv4_ping(first_host, second_host.IP())


class FaucetUntaggedIPv4ControlPlaneFuzzTest(FaucetUntaggedTest):

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


    def test_ping_fragment_controller(self):
        first_host = self.net.hosts[0]
        first_host.cmd('ping -s 1476 -c 3 %s' % self.FAUCET_VIPV4.ip)
        self.one_ipv4_controller_ping(first_host)

    def test_fuzz_controller(self):
        first_host = self.net.hosts[0]
        self.one_ipv4_controller_ping(first_host)
        packets = 1000
        for fuzz_cmd in (
                ('python -c \"from scapy.all import * ;'
                 'scapy.all.send(IP(dst=\'%s\')/'
                 'fuzz(%s(type=0)),count=%u)\"' % (self.FAUCET_VIPV4.ip, 'ICMP', packets)),
                ('python -c \"from scapy.all import * ;'
                 'scapy.all.send(IP(dst=\'%s\')/'
                 'fuzz(%s(type=8)),count=%u)\"' % (self.FAUCET_VIPV4.ip, 'ICMP', packets)),
                ('python -c \"from scapy.all import * ;'
                 'scapy.all.send(fuzz(%s(pdst=\'%s\')),'
                 'count=%u)\"' % ('ARP', self.FAUCET_VIPV4.ip, packets))):
            self.assertTrue(
                re.search('Sent %u packets' % packets, first_host.cmd(fuzz_cmd)))
        self.one_ipv4_controller_ping(first_host)

    def test_flap_ping_controller(self):
        first_host, second_host = self.net.hosts[0:2]
        for _ in range(5):
            self.one_ipv4_ping(first_host, second_host.IP())
            for host in first_host, second_host:
                self.one_ipv4_controller_ping(host)
            self.flap_all_switch_ports()


class FaucetSingleUntaggedIPv4ControlPlaneTest(FaucetUntaggedTest):

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

    def test_fping_controller(self):
        first_host = self.net.hosts[0]
        self.one_ipv4_controller_ping(first_host)
        self.verify_controller_fping(first_host, self.FAUCET_VIPV4)


class FaucetUntaggedIPv6RATest(FaucetUntaggedTest):

    FAUCET_MAC = "0e:00:00:00:00:99"

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fe80::1:254/64", "fc00::1:254/112", "fc00::2:254/112", "10.0.0.254/24"]
        faucet_mac: "%s"
""" % FAUCET_MAC

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
            self.assertEqual(
                self.FAUCET_MAC.upper(),
                first_host.cmd('ndisc6 -q %s %s' % (vip, first_host.defaultIntf())).strip())

    def test_rdisc6(self):
        first_host = self.net.hosts[0]
        rdisc6_results = sorted(list(set(first_host.cmd(
            'rdisc6 -q %s' % first_host.defaultIntf()).splitlines())))
        self.assertEqual(
            ['fc00::1:0/112', 'fc00::2:0/112'],
            rdisc6_results)

    def test_ra_advertise(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = ' and '.join((
            'ether dst 33:33:00:00:00:01',
            'ether src %s' % self.FAUCET_MAC,
            'icmp6',
            'ip6[40] == 134',
            'ip6 host fe80::1:254'))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [], timeout=30, vflags='-vv', packets=1)
        for ra_required in (
                r'fe80::1:254 > ff02::1:.+ICMP6, router advertisement',
                r'fc00::1:0/112, Flags \[onlink, auto\]',
                r'fc00::2:0/112, Flags \[onlink, auto\]',
                r'source link-address option \(1\), length 8 \(1\): %s' % self.FAUCET_MAC):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg='%s: %s' % (ra_required, tcpdump_txt))

    def test_rs_reply(self):
        first_host = self.net.hosts[0]
        tcpdump_filter = ' and '.join((
            'ether src %s' % self.FAUCET_MAC,
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
                r'source link-address option \(1\), length 8 \(1\): %s' % self.FAUCET_MAC):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg='%s: %s (%s)' % (ra_required, tcpdump_txt, tcpdump_filter))


class FaucetUntaggedIPv6ControlPlaneFuzzTest(FaucetUntaggedTest):

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

    def test_flap_ping_controller(self):
        first_host, second_host = self.net.hosts[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        for _ in range(5):
            self.one_ipv6_ping(first_host, 'fc00::1:2')
            for host in first_host, second_host:
                self.one_ipv6_controller_ping(host)
            self.flap_all_switch_ports()

    def test_fuzz_controller(self):
        first_host = self.net.hosts[0]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.one_ipv6_controller_ping(first_host)
        fuzz_success = False
        packets = 1000
        for fuzz_class in dir(scapy.all):
            if fuzz_class.startswith('ICMPv6'):
                fuzz_cmd = (
                    'python -c \"from scapy.all import * ;'
                    'scapy.all.send(IPv6(dst=\'%s\')/'
                    'fuzz(%s()),count=%u)\"' % (self.FAUCET_VIPV6.ip, fuzz_class, packets))
                if re.search('Sent %u packets' % packets, first_host.cmd(fuzz_cmd)):
                    output(fuzz_class)
                    fuzz_success = True
        self.assertTrue(fuzz_success)
        self.one_ipv6_controller_ping(first_host)


class FaucetSingleUntaggedIPv6ControlPlaneTest(FaucetUntaggedTest):

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

    def test_fping_controller(self):
        first_host = self.net.hosts[0]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.one_ipv6_controller_ping(first_host)
        self.verify_controller_fping(first_host, self.FAUCET_VIPV6)


class FaucetTaggedAndUntaggedDiffVlanTest(FaucetTest):

    N_TAGGED = 2
    N_UNTAGGED = 4
    LINKS_PER_HOST = 1
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

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetTaggedAndUntaggedDiffVlanTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=2, n_untagged=2, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_separate_untagged_tagged(self):
        tagged_host_pair = self.net.hosts[:2]
        untagged_host_pair = self.net.hosts[2:]
        self.verify_vlan_flood_limited(
            tagged_host_pair[0], tagged_host_pair[1], untagged_host_pair[0])
        self.verify_vlan_flood_limited(
            untagged_host_pair[0], untagged_host_pair[1], tagged_host_pair[0])
        # hosts within VLANs can ping each other
        self.retry_net_ping(hosts=tagged_host_pair)
        self.retry_net_ping(hosts=untagged_host_pair)
        # hosts cannot ping hosts in other VLANs
        self.assertEqual(
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
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
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

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetUntaggedDPACLTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
"""
    CONFIG = """
        dp_acls: [1]
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
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetUntaggedNoReconfACLTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
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
                opstatus_reconf: False
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
        matches = {
            u'in_port': int(self.port_map['port_1']),
            u'tcp_dst': 5001,
            u'eth_type': 0x800,
            u'ip_proto': 6}
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.wait_until_matching_flow(
            matches, table_id=self._PORT_ACL_TABLE, actions=[])
        self.set_port_down(self.port_map['port_1'])
        self.wait_until_matching_flow(
            matches, table_id=self._PORT_ACL_TABLE, actions=[])
        self.set_port_up(self.port_map['port_1'])
        self.ping_all_when_learned()
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.wait_until_matching_flow(
            matches, table_id=self._PORT_ACL_TABLE, actions=[])


class FaucetUntaggedACLTcpMaskTest(FaucetUntaggedACLTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    1:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            # Match packets > 1023
            tcp_dst: 1024/1024
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
"""

    def test_port_gt1023_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(1024, first_host, second_host, mask=1024)
        self.verify_tp_dst_notblocked(1023, first_host, second_host, table_id=None)


class FaucetUntaggedVLANACLTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
acls:
    1:
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5001
            actions:
                allow: 0
        - rule:
            dl_type: 0x800
            ip_proto: 6
            tcp_dst: 5002
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
            5001, first_host, second_host, table_id=self._VLAN_ACL_TABLE)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=self._VLAN_ACL_TABLE)


class FaucetZodiacUntaggedACLTest(FaucetUntaggedACLTest):

    RUN_GAUGE = False
    N_UNTAGGED = 3

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.ping_all_when_learned()


class FaucetUntaggedOutputOnlyTest(FaucetUntaggedTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                output_only: True
                description: "b1"
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                number: %(port_3)d
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        self.wait_until_matching_flow(
            {u'in_port': int(self.port_map['port_1'])},
            table_id=self._VLAN_TABLE,
            actions=[])
        first_host, second_host, third_host = self.net.hosts[:3]
        self.assertEqual(100.0, self.net.ping((first_host, second_host)))
        self.assertEqual(0, self.net.ping((third_host, second_host)))


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


class FaucetMultiOutputTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
    200:
acls:
    multi_out:
        - rule:
            actions:
                output:
                    ports: [ output2, output3 ]
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: multi_out
            output2:
                number: %(port_2)d
                native_vlan: 100
            output3:
                number: %(port_3)d
                native_vlan: 200
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, third_host, fourth_host = self.net.hosts[0:4]
        tcpdump_filter = ('icmp')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            third_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (third_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1 %s' % third_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % third_host.IP(), tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            fourth_host, tcpdump_filter, [
                lambda: first_host.cmd('ping -c1 %s' % fourth_host.IP())])
        self.assertFalse(re.search(
            '%s: ICMP echo request' % fourth_host.IP(), tcpdump_txt))


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
                    vlan_vid: 123
                    set_fields:
                        - eth_dst: "06:06:06:06:06:06"
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
                    set_fields:
                        - eth_dst: "06:06:06:06:06:06"
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


@unittest2.skip('190318: works under OVS 2.9.2 locally, but not under Travis')
class FaucetUntaggedMultiConfVlansOutputTest(FaucetUntaggedTest):

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
                    set_fields:
                        - eth_dst: "06:06:06:06:06:06"
                    vlan_vids: [{vid: 123, eth_type: 0x88a8}, 456]
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
        tcpdump_filter = 'ether proto 0x88a8'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 456.+ethertype 802.1Q-QinQ, vlan 123', tcpdump_txt))


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
                # port 3 will mirror port 1
                description: "b3"
                mirror: %(port_1)d
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.net.hosts[0:3]
        self.flap_all_switch_ports()
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        self.verify_bcast_ping_mirrored(first_host, second_host, mirror_host)


class FaucetUntaggedOutputOverrideTest(FaucetUntaggedTest):

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
                override_output_port: %(port_3)d
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                description: "b3"
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        first_host, second_host, override_host = self.net.hosts[0:3]
        self.flap_all_switch_ports()
        first_host.cmd('arp -s %s %s' % (second_host.IP(), second_host.MAC()))
        second_host.cmd('arp -s %s %s' % (first_host.IP(), first_host.MAC()))
        tcpdump_filter = (
            'ether src %s and icmp[icmptype] == 8') % first_host.MAC()
        tcpdump_txt = self.tcpdump_helper(
            override_host, tcpdump_filter, [
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)
        tcpdump_filter = (
            'ether src %s and icmp[icmptype] == 8') % second_host.MAC()
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: second_host.cmd('ping -c1 %s' % first_host.IP())])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % first_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)


class FaucetUntaggedMultiMirrorTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                name: b1
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                name: b2
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                description: "b3"
                output_only: True
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.net.hosts[:3]
        ping_pairs = (
            (first_host, second_host),
            (second_host, first_host))
        self.flap_all_switch_ports()
        self.change_port_config(
            self.port_map['port_3'], 'mirror', ['b1', 'b2'],
            restart=True, cold_start=True, hup=True)
        self.verify_ping_mirrored_multi(
            ping_pairs, mirror_host, both_mirrored=True)


class FaucetUntaggedMultiMirrorSepTest(FaucetUntaggedTest):

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
                description: "b3"
                mirror: %(port_1)d
            %(port_4)d:
                description: "b4"
                mirror: %(port_1)d
"""

    def test_untagged(self):
        self.flap_all_switch_ports()

        # Make sure the two hosts both mirror from port 1
        first_host, second_host = self.net.hosts[0:2]
        mirror_host = self.net.hosts[2]
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        mirror_host = self.net.hosts[3]
        self.verify_ping_mirrored(first_host, second_host, mirror_host)


class FaucetTaggedTest(FaucetTest):

    N_UNTAGGED = 0
    N_TAGGED = 4
    LINKS_PER_HOST = 1
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

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetTaggedTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=4, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_tagged(self):
        self.ping_all_when_learned()


class FaucetTaggedScaleTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
""" + '\n'.join(['\n'.join(('    %u:', '        description: "tagged"')) %
                 i for i in range(100, 164)])
    CONFIG = """
        interfaces:
            %s:
                tagged_vlans: [%s]
                description: "b1"
            %s:
                tagged_vlans: [%s]
                description: "b2"
            %s:
                tagged_vlans: [%s]
                description: "b3"
            %s:
                tagged_vlans: [%s]
                description: "b4"
""" % ('%(port_1)d', ','.join([str(i) for i in range(100, 164)]),
       '%(port_2)d', ','.join([str(i) for i in range(100, 164)]),
       '%(port_3)d', ','.join([str(i) for i in range(100, 164)]),
       '%(port_4)d', ','.join([str(i) for i in range(100, 164)]))


    def test_tagged(self):
        self.ping_all_when_learned()
        for host in self.net.hosts:
            setup_commands = []
            for i in range(101, 164):
                setup_commands.extend([
                    'ip link add link %s name %s.%u type vlan id %u' % (
                        host.intf_root_name, host.intf_root_name, i, i),
                    'ip link set dev %s.%u up' % (
                        host.intf_root_name, i)])
            self.quiet_commands(host, setup_commands)
        for host in self.net.hosts:
            rdisc6_commands = []
            for i in range(101, 164):
                rdisc6_commands.append(
                    'rdisc6 -r2 -w1 -q %s.%u 2> /dev/null' % (
                        host.intf_root_name, i))
            self.quiet_commands(host, rdisc6_commands)
        for vlan in range(101, 164):
            for _ in range(3):
                for host in self.net.hosts:
                    self.quiet_commands(
                        host,
                        ['rdisc6 -r2 -w1 -q %s.%u 2> /dev/null' % (
                            host.intf_root_name, i)])
                vlan_hosts_learned = self.scrape_prometheus_var(
                    'vlan_hosts_learned', {'vlan': str(vlan)})
                if vlan_hosts_learned == len(self.net.hosts):
                    break
                time.sleep(1)
            self.assertGreater(
                vlan_hosts_learned, 1,
                msg='not all VLAN %u hosts learned (%u)' % (vlan, vlan_hosts_learned))


class FaucetTaggedBroadcastTest(FaucetTaggedTest):

    def test_tagged(self):
        super(FaucetTaggedBroadcastTest, self).test_tagged()
        self.verify_broadcast()
        self.verify_no_bcast_to_self(self.net.hosts[0])


class FaucetTaggedWithUntaggedTest(FaucetTaggedTest):

    N_UNTAGGED = 0
    N_TAGGED = 4
    LINKS_PER_HOST = 1
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
    200:
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 200
                tagged_vlans: [100]
                description: "b1"
            %(port_2)d:
                native_vlan: 200
                tagged_vlans: [100]
                description: "b2"
            %(port_3)d:
                native_vlan: 200
                tagged_vlans: [100]
                description: "b3"
            %(port_4)d:
                native_vlan: 200
                tagged_vlans: [100]
                description: "b4"
"""

    def test_tagged(self):
        self.ping_all_when_learned()
        native_ips = [
            ipaddress.ip_interface(u'10.99.99.%u/24' % (i + 1)) for i in range(len(self.net.hosts))]
        for native_ip, host in zip(native_ips, self.net.hosts):
            self.host_ipv4_alias(host, native_ip, intf=host.intf_root_name)
        for own_native_ip, host in zip(native_ips, self.net.hosts):
            for native_ip in native_ips:
                if native_ip != own_native_ip:
                    self.one_ipv4_ping(host, native_ip.ip, intf=host.intf_root_name)


class FaucetTaggedSwapVidMirrorTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
    101:
        description: "tagged"
acls:
    1:
        - rule:
            vlan_vid: 100
            actions:
                mirror: mirrorport
                force_port_vlan: 1
                output:
                    swap_vid: 101
                allow: 1
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                description: "b1"
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [101]
                description: "b2"
            mirrorport:
                number: %(port_3)d
                tagged_vlans: [100]
                description: "b3"
            %(port_4)d:
                tagged_vlans: [100]
                description: "b4"
    """

    def test_tagged(self):
        first_host, second_host, third_host = self.net.hosts[:3]

        def test_acl(tcpdump_host, tcpdump_filter):
            tcpdump_txt = self.tcpdump_helper(
                tcpdump_host, tcpdump_filter, [
                    lambda: first_host.cmd(
                        'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                    lambda: first_host.cmd('ping -c1 %s' % second_host.IP())], root_intf=True)
            self.assertTrue(re.search(
                '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
            self.assertTrue(re.search(
                tcpdump_filter, tcpdump_txt))

        # Saw swapped VID on second host
        test_acl(second_host, 'vlan 101')
        # Saw original VID on mirror host
        test_acl(third_host, 'vlan 100')


class FaucetTaggedSwapVidOutputTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        unicast_flood: False
    101:
        description: "tagged"
        unicast_flood: False
acls:
    1:
        - rule:
            vlan_vid: 100
            actions:
                output:
                    swap_vid: 101
                    port: acloutport
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                description: "b1"
                acl_in: 1
            acloutport:
                number: %(port_2)d
                tagged_vlans: [101]
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
        # we expected to see the swapped VLAN VID
        tcpdump_filter = 'vlan 101'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    'arp -s %s %s' % (second_host.IP(), '01:02:03:04:05:06')),
                lambda: first_host.cmd('ping -c1 %s' % second_host.IP())], root_intf=True)
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 101', tcpdump_txt))


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
                    set_fields:
                        - eth_dst: "06:06:06:06:06:06"
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


class FaucetTaggedICMPv6ACLTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
acls:
    1:
        - rule:
            dl_type: 0x86dd
            vlan_vid: 100
            ip_proto: 58
            icmpv6_type: 135
            ipv6_nd_target: "fc00::1:2"
            actions:
                output:
                    port: b2
        - rule:
            actions:
                allow: 1
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
                acl_in: 1
            b2:
                number: %(port_2)d
                tagged_vlans: [100]
                description: "b2"
            %(port_3)d:
                tagged_vlans: [100]
                description: "b3"
            %(port_4)d:
                tagged_vlans: [100]
                description: "b4"
"""

    def test_icmpv6_acl_match(self):
        first_host, second_host = self.net.hosts[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        self.wait_nonzero_packet_count_flow(
            {u'ipv6_nd_target': u'fc00::1:2'}, table_id=self._PORT_ACL_TABLE)


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
    200:
        description: "not used"
    300:
        description: "not used"
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
                native_vlan: 200
                description: "b4"
"""

    def test_tagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddress.ip_interface(u'10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface(u'10.0.2.1/24')
        for _coldstart in range(2):
            for _swaps in range(3):
                self.verify_ipv4_routing(
                    first_host, first_host_routed_ip,
                    second_host, second_host_routed_ip)
                self.swap_host_macs(first_host, second_host)
            self.coldstart_conf()
        # change of a VLAN/ports not involved in routing, should be a warm start.
        for vid in (300, 200):
            self.change_port_config(
                self.port_map['port_4'], 'native_vlan', vid,
                restart=True, cold_start=False)


class FaucetTaggedTargetedResolutionIPv4RouteTest(FaucetTaggedIPv4RouteTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["10.0.0.254/24"]
        targeted_gw_resolution: True
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

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["10.100.0.254/24"]
    vlanb:
        vid: 200
        faucet_vips: ["10.200.0.254/24"]
        faucet_mac: "%s"
    vlanc:
        vid: 100
        description: "not used"
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                native_vlan: vlanb
                description: "b2"
            %(port_3)d:
                native_vlan: vlanb
                description: "b3"
            %(port_4)d:
                native_vlan: vlanb
                description: "b4"
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface(u'10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface(u'10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface(u'10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface(u'10.200.0.254/24')
        first_host, second_host = self.net.hosts[:2]
        first_host.setIP(str(first_host_ip.ip), prefixLen=24)
        second_host.setIP(str(second_host_ip.ip), prefixLen=24)
        self.add_host_route(first_host, second_host_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)

        for vlanb_vid in (300, 200):
            self.one_ipv4_ping(first_host, second_host_ip.ip)
            self.one_ipv4_ping(second_host, first_host_ip.ip)
            self.assertEqual(
                self._ip_neigh(first_host, first_faucet_vip.ip, 4), self.FAUCET_MAC)
            self.assertEqual(
                self._ip_neigh(second_host, second_faucet_vip.ip, 4), self.FAUCET_MAC2)
            self.change_vlan_config(
                'vlanb', 'vid', vlanb_vid, restart=True, cold_start=True)


class FaucetUntaggedExpireIPv4InterVLANRouteTest(FaucetUntaggedTest):

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["10.100.0.254/24"]
    vlanb:
        vid: 200
        faucet_vips: ["10.200.0.254/24"]
        faucet_mac: "%s"
    vlanc:
        vid: 100
        description: "not used"
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        max_host_fib_retry_count: 2
        proactive_learn: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                native_vlan: vlanb
                description: "b2"
            %(port_3)d:
                native_vlan: vlanb
                description: "b3"
            %(port_4)d:
                native_vlan: vlanb
                description: "b4"
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface(u'10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface(u'10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface(u'10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface(u'10.200.0.254/24')
        first_host, second_host = self.net.hosts[:2]
        first_host.setIP(str(first_host_ip.ip), prefixLen=24)
        second_host.setIP(str(second_host_ip.ip), prefixLen=24)
        self.add_host_route(first_host, second_host_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)
        second_host.cmd('ifconfig %s down' % second_host.defaultIntf().name)
        log_file_name = os.path.join(self.tmpdir, 'faucet.log')
        expired_re = r'.+expiring dead route %s.+' % second_host_ip.ip
        found_expired = False
        for _ in range(30):
            if self.matching_lines_from_file(expired_re, log_file_name):
                found_expired = True
                break
            time.sleep(1)
        self.assertTrue(found_expired, msg=expired_re)
        second_host.cmd('ifconfig %s up' % second_host.defaultIntf().name)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)


class FaucetUntaggedIPv6InterVLANRouteTest(FaucetUntaggedTest):

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["fc00::1:254/112"]
    vlanb:
        vid: 200
        faucet_vips: ["fc01::1:254/112"]
        faucet_mac: "%s"
    vlanc:
        vid: 100
        description: "not used"
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                native_vlan: vlanb
                description: "b2"
            %(port_3)d:
                native_vlan: vlanb
                description: "b3"
            %(port_4)d:
                native_vlan: vlanb
                description: "b4"
"""

    def test_untagged(self):
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddress.ip_interface(u'fc00::1:1/64')
        second_host_net = ipaddress.ip_interface(u'fc01::1:1/64')
        self.add_host_ipv6_address(first_host, first_host_net)
        self.add_host_ipv6_address(second_host, second_host_net)
        self.add_host_route(
            first_host, second_host_net, self.FAUCET_VIPV6.ip)
        self.add_host_route(
            second_host, first_host_net, self.FAUCET_VIPV6_2.ip)
        self.one_ipv6_ping(first_host, second_host_net.ip)
        self.one_ipv6_ping(second_host, first_host_net.ip)


class FaucetUntaggedIPv4PolicyRouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "100"
        faucet_vips: ["10.0.0.254/24"]
        acl_in: pbr
    200:
        description: "200"
        faucet_vips: ["10.20.0.254/24"]
        routes:
            - route:
                ip_dst: "10.99.0.0/24"
                ip_gw: "10.20.0.2"
    300:
        description: "300"
        faucet_vips: ["10.30.0.254/24"]
        routes:
            - route:
                ip_dst: "10.99.0.0/24"
                ip_gw: "10.30.0.3"
acls:
    pbr:
        - rule:
            vlan_vid: 100
            dl_type: 0x800
            nw_dst: "10.99.0.2"
            actions:
                allow: 1
                output:
                    swap_vid: 300
        - rule:
            vlan_vid: 100
            dl_type: 0x800
            nw_dst: "10.99.0.0/24"
            actions:
                allow: 1
                output:
                    swap_vid: 200
        - rule:
            actions:
                allow: 1
routers:
    router-100-200:
        vlans: [100, 200]
    router-100-300:
        vlans: [100, 300]
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
                native_vlan: 300
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def test_untagged(self):
        # 10.99.0.1 is on b2, and 10.99.0.2 is on b3
        # we want to route 10.99.0.0/24 to b2, but we want
        # want to PBR 10.99.0.2/32 to b3.
        first_host_ip = ipaddress.ip_interface(u'10.0.0.1/24')
        first_faucet_vip = ipaddress.ip_interface(u'10.0.0.254/24')
        second_host_ip = ipaddress.ip_interface(u'10.20.0.2/24')
        second_faucet_vip = ipaddress.ip_interface(u'10.20.0.254/24')
        third_host_ip = ipaddress.ip_interface(u'10.30.0.3/24')
        third_faucet_vip = ipaddress.ip_interface(u'10.30.0.254/24')
        first_host, second_host, third_host = self.net.hosts[:3]
        remote_ip = ipaddress.ip_interface(u'10.99.0.1/24')
        remote_ip2 = ipaddress.ip_interface(u'10.99.0.2/24')
        second_host.setIP(str(second_host_ip.ip), prefixLen=24)
        third_host.setIP(str(third_host_ip.ip), prefixLen=24)
        self.host_ipv4_alias(second_host, remote_ip)
        self.host_ipv4_alias(third_host, remote_ip2)
        self.add_host_route(first_host, remote_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.add_host_route(third_host, first_host_ip, third_faucet_vip.ip)
        # ensure all nexthops resolved.
        self.one_ipv4_ping(first_host, first_faucet_vip.ip)
        self.one_ipv4_ping(second_host, second_faucet_vip.ip)
        self.one_ipv4_ping(third_host, third_faucet_vip.ip)
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv4Network(u'10.99.0.0/24'), vlan_vid=200)
        self.wait_for_route_as_flow(
            third_host.MAC(), ipaddress.IPv4Network(u'10.99.0.0/24'), vlan_vid=300)
        # verify b1 can reach 10.99.0.1 and .2 on b2 and b3 respectively.
        self.one_ipv4_ping(first_host, remote_ip.ip)
        self.one_ipv4_ping(first_host, remote_ip2.ip)


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
        second_host.setIP(str(second_host_net.ip), prefixLen=24)
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
        faucet_vips: ["fc00::1:254/112", "fc01::1:254/112"]
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
        bgp_server_addresses: ["::1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["::1"]
        bgp_connect_mode: "passive"
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_peer_conf = """
    static {
      route ::/0 next-hop fc00::1:1 local-preference 100;
    }
"""

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1', self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        first_host_alias_ip = ipaddress.ip_interface(u'fc00::50:1/112')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.add_host_ipv6_address(first_host, first_host_alias_ip)
        self.wait_bgp_up('::1', 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV6.ip)
        self.one_ipv6_ping(second_host, first_host_alias_ip.ip)
        self.one_ipv6_controller_ping(first_host)
        self.coldstart_conf()


class FaucetUntaggedBGPIPv6RouteTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
        bgp_port: %(bgp_port)d
        bgp_server_addresses: ["::1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["::1"]
        bgp_connect_mode: "passive"
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_peer_conf = """
    static {
      route fc00::10:1/112 next-hop fc00::1:1 local-preference 100;
      route fc00::20:1/112 next-hop fc00::1:2 local-preference 100;
      route fc00::30:1/112 next-hop fc00::1:2 local-preference 100;
      route fc00::40:1/112 next-hop fc00::1:254;
      route fc00::50:1/112 next-hop fc00::2:2;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1', self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        first_host, second_host = self.net.hosts[:2]
        self.wait_bgp_up('::1', 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route(r'.+fc00::40:0\/112 cannot be us$')
        self.verify_invalid_bgp_route(r'.+fc00::50:0\/112 is not a connected network$')
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
        bgp_server_addresses: ["::1"]
        bgp_as: 1
        bgp_routerid: "1.1.1.1"
        bgp_neighbor_addresses: ["::1"]
        bgp_connect_mode: "passive"
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
""" + """
        bgp_neighbor_as: %u
""" % PEER_BGP_AS

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

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}


    def pre_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1')
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        self.verify_ipv6_routing_mesh()
        second_host = self.net.hosts[1]
        self.flap_all_switch_ports()
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv6Network(u'fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        self.wait_bgp_up('::1', 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        updates = self.exabgp_updates(self.exabgp_log)
        self.assertTrue(re.search('fc00::1:0/112 next-hop fc00::1:254', updates))
        self.assertTrue(re.search('fc00::10:0/112 next-hop fc00::1:1', updates))
        self.assertTrue(re.search('fc00::20:0/112 next-hop fc00::1:2', updates))
        self.assertTrue(re.search('fc00::30:0/112 next-hop fc00::1:2', updates))


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
        for _coldstart in range(2):
            for _swaps in range(5):
                self.verify_ipv6_routing_pair(
                    first_host, first_host_ip, first_host_routed_ip,
                    second_host, second_host_ip, second_host_routed_ip)
                self.swap_host_macs(first_host, second_host)
            self.coldstart_conf()


class FaucetStringOfDPTest(FaucetTest):

    NUM_HOSTS = 4
    LINKS_PER_HOST = 1
    VID = 100
    CONFIG = None
    dpids = None
    topo = None

    @staticmethod
    def get_config_header(_config_global, _debug_log, _dpid, _hardware):
        """Don't generate standard config file header."""
        return ''

    def build_net(self, stack=False, n_dps=1,
                  n_tagged=0, tagged_vid=100,
                  n_untagged=0, untagged_vid=100,
                  include=None, include_optional=None,
                  acls=None, acl_in_dp=None,
                  switch_to_switch_links=1, hw_dpid=None):
        """Set up Mininet and Faucet for the given topology."""
        if include is None:
            include = []
        if include_optional is None:
            include_optional = []
        if acls is None:
            acls = {}
        if acl_in_dp is None:
            acl_in_dp = {}
        self.dpids = [str(self.rand_dpid()) for _ in range(n_dps)]
        self.dpids[0] = self.dpid
        self.topo = mininet_test_topo.FaucetStringOfDPSwitchTopo(
            self.OVS_TYPE,
            self.ports_sock,
            dpids=self.dpids,
            n_tagged=n_tagged,
            tagged_vid=tagged_vid,
            n_untagged=n_untagged,
            links_per_host=self.LINKS_PER_HOST,
            switch_to_switch_links=switch_to_switch_links,
            test_name=self._test_name(),
            hw_dpid=hw_dpid,
        )
        self.CONFIG = self.get_config(
            self.dpids,
            hw_dpid,
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
        self._write_faucet_config()

    def get_config(self, dpids=None, hw_dpid=None, stack=False, hardware=None, ofchannel_log=None,
                   n_tagged=0, tagged_vid=0, n_untagged=0, untagged_vid=0,
                   include=None, include_optional=None, acls=None, acl_in_dp=None):
        """Build a complete Faucet configuration for each datapath, using the given topology."""
        if dpids is None:
            dpids = []
        if include is None:
            include = []
        if include_optional is None:
            include_optional = []
        if acls is None:
            acls = {}
        if acl_in_dp is None:
            acl_in_dp = {}

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

            def stack_name(name, port):
                return '%s_%u' % (dp_name(name), port)

            # Add configuration for the switch-to-switch links
            # (0 for a single switch, 1 for an end switch, 2 for middle switches).
            first_dp = i == 0
            second_dp = i == 1
            last_dp = i == dpid_count - 1
            end_dp = first_dp or last_dp
            first_stack_port = port
            peer_dps = []
            if dpid_count > 1:
                if end_dp:
                    if first_dp:
                        peer_dps = [i + 1]
                    else:
                        peer_dps = [i - 1]
                else:
                    peer_dps = [i - 1, i + 1]

                # TODO: make the stacking root configurable
                if stack and first_dp:
                    dp_config['stack'] = {
                        'priority': 1
                    }
                for peer_dp in peer_dps:
                    if first_dp or second_dp:
                        peer_stack_port_base = first_stack_port
                    else:
                        peer_stack_port_base = first_stack_port + self.topo.switch_to_switch_links
                    for stack_dp_port in range(self.topo.switch_to_switch_links):
                        peer_port = peer_stack_port_base + stack_dp_port
                        description = 'to %s port %u' % (dp_name(peer_dp), peer_port)
                        interfaces_config[port] = {
                            'name': stack_name(i, port),
                            'description': description,
                        }
                        if stack:
                            # make this a stacking link.
                            interfaces_config[port].update(
                                {
                                    'lldp_beacon': {
                                        'enable': True},
                                    'receive_lldp': True,
                                    'stack': {
                                        'dp': dp_name(peer_dp),
                                        'port': stack_name(peer_dp, peer_port)}
                                })
                        else:
                            # not a stack - make this a trunk.
                            tagged_vlans = []
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

        def add_dp(name, dpid, hw_dpid, i, dpid_count, stack,
                   n_tagged, tagged_vid, n_untagged, untagged_vid):
            dpid_ofchannel_log = None
            if ofchannel_log is not None:
                dpid_ofchannel_log = ofchannel_log + str(i)
            dp_hardware = hardware
            if dpid != hw_dpid:
                dp_hardware = 'Open vSwitch'
            dp_config = {
                'dp_id': int(dpid),
                'hardware': dp_hardware,
                'ofchannel_log': dpid_ofchannel_log,
                'interfaces': {},
                'lldp_beacon': {'send_interval': 5, 'max_per_interval': 5},
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

            if dpid == hw_dpid:
                for interface, config in list(interfaces_config.items()):
                    del interfaces_config[interface]
                    mapped_interface = self.port_map['port_%u' % interface]
                    interfaces_config[mapped_interface] = config

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
                name, dpid, hw_dpid, i, dpid_count, stack,
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

    def verify_no_cable_errors(self):
        i = 0
        for dpid in self.dpids:
            i += 1
            labels = {'dp_id': '0x%x' % int(dpid), 'dp_name': 'faucet-%u' % i}
            self.assertEquals(
                0, self.scrape_prometheus_var(var='stack_cabling_errors', labels=labels, default=0))
            self.assertGreater(
                self.scrape_prometheus_var(var='stack_probes_received', labels=labels), 0)

    def verify_stack_hosts(self, verify_bridge_local_rule=True):
        lldp_cap_files = []
        for host in self.net.hosts:
            lldp_cap_file = os.path.join(self.tmpdir, '%s-lldp.cap' % host)
            lldp_cap_files.append(lldp_cap_file)
            host.cmd(mininet_test_util.timeout_cmd(
                'tcpdump -U -n -c 1 -i %s -w %s ether proto 0x88CC &' % (
                    host.defaultIntf(), lldp_cap_file), 60))
        for _ in range(3):
            self.retry_net_ping()
        # hosts should see no LLDP probes
        for lldp_cap_file in lldp_cap_files:
            self.quiet_commands(
                self.net.controllers[0],
                ['tcpdump -n -r %s 2> /dev/null' % lldp_cap_file])
        # should not flood LLDP from hosts
        self.verify_lldp_blocked(self.net.hosts)
        if verify_bridge_local_rule:
            # Verify 802.1x flood block triggered.
            for dpid in self.dpids:
                self.wait_nonzero_packet_count_flow(
                    {u'dl_dst': u'01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0'},
                    dpid=dpid,
                    table_id=self._FLOOD_TABLE)


class FaucetStringOfDPUntaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetStringOfDPUntaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_untagged=self.NUM_HOSTS, untagged_vid=self.VID)
        self.start_net()

    def test_untagged(self):
        """All untagged hosts in multi switch topology can reach one another."""
        self.verify_stack_hosts()


class FaucetStringOfDPTaggedTest(FaucetStringOfDPTest):

    NUM_DPS = 3

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetStringOfDPTaggedTest, self).setUp()
        self.build_net(
            n_dps=self.NUM_DPS, n_tagged=self.NUM_HOSTS, tagged_vid=self.VID)
        self.start_net()

    def test_tagged(self):
        """All tagged hosts in multi switch topology can reach one another."""
        self.verify_stack_hosts(verify_bridge_local_rule=False)


class FaucetSingleStackStringOfDPTaggedTest(FaucetStringOfDPTest):
    """Test topology of stacked datapaths with tagged hosts."""

    NUM_DPS = 3

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetSingleStackStringOfDPTaggedTest, self).setUp()
        self.build_net(
            stack=True,
            n_dps=self.NUM_DPS,
            n_tagged=self.NUM_HOSTS,
            tagged_vid=self.VID,
            switch_to_switch_links=2)
        self.start_net()

    def verify_one_stack_down(self, port_no, coldstart=False):
        switch_port_key = 'port_%u' % port_no
        if switch_port_key in self.port_map:
            port_no = self.port_map[switch_port_key]
        self.retry_net_ping()
        self.set_port_down(port_no, wait=False)
        # self.dpids[1] is the intermediate switch.
        self.set_port_down(port_no, self.dpids[1], wait=False)
        # test case where one link is down when coldstarted.
        if coldstart:
            self.coldstart_conf()
        self.verify_stack_hosts(verify_bridge_local_rule=False)
        # Broadcast works, and first switch doesn't see broadcast packet ins from stack.
        packet_in_before_broadcast = self.scrape_prometheus_var('of_vlan_packet_ins')
        self.verify_broadcast()
        packet_in_after_broadcast = self.scrape_prometheus_var('of_vlan_packet_ins')
        self.assertEqual(
            packet_in_before_broadcast,
            packet_in_after_broadcast)
        # TODO: re-enable.
        # self.verify_no_cable_errors()

    def test_tagged(self):
        """All tagged hosts in stack topology can reach each other."""
        for coldstart in (False, True):
            self.verify_one_stack_down(self.NUM_HOSTS + 1, coldstart)

    def test_other_tagged(self):
        for coldstart in (False, True):
            self.verify_one_stack_down(self.NUM_HOSTS + 2, coldstart)


class FaucetStackStringOfDPUntaggedTest(FaucetStringOfDPTest):
    """Test topology of stacked datapaths with untagged hosts."""

    NUM_DPS = 2
    NUM_HOSTS = 2

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetStackStringOfDPUntaggedTest, self).setUp()
        self.build_net(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            untagged_vid=self.VID,
            switch_to_switch_links=2,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_untagged(self):
        """All untagged hosts in stack topology can reach each other."""
        self.verify_stack_hosts()
        self.verify_no_cable_errors()


class FaucetSingleStackAclControlTest(FaucetStringOfDPTest):
    """Test ACL control of stacked datapaths with untagged hosts."""

    NUM_DPS = 3
    NUM_HOSTS = 3

    ACLS = {
        1: [
            {'rule': {
                'dl_type': '0x800',
                'nw_dst': '10.0.0.2',
                'actions': {
                    'output': {
                        'port': 2
                    }
                },
            }},
            {'rule': {
                'dl_type': '0x800',
                'dl_dst': 'ff:ff:ff:ff:ff:ff',
                'actions': {
                    'output': {
                        'ports': [2, 4]
                    }
                },
            }},
            {'rule': {
                'dl_type': '0x800',
                'actions': {
                    'output': {
                        'port': 4
                    }
                },
            }},
            {'rule': {
                'actions': {
                    'allow': 1,
                },
            }},
        ],
        2: [
            {'rule': {
                'dl_type': '0x800',
                'actions': {
                    'output': {
                        'port': 5
                    }
                },
            }},
            {'rule': {
                'actions': {
                    'allow': 1,
                },
            }},
        ],
        3: [
            {'rule': {
                'dl_type': '0x800',
                'nw_dst': '10.0.0.7',
                'actions': {
                    'output': {
                        'port': 1
                    }
                },
            }},
            {'rule': {
                'dl_type': '0x800',
                'dl_dst': 'ff:ff:ff:ff:ff:ff',
                'actions': {
                    'output': {
                        'ports': [1]
                    }
                },
            }},
            {'rule': {
                'dl_type': '0x800',
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

    # DP-to-acl_in port mapping.
    ACL_IN_DP = {
        'faucet-1': {
            # Port 1, acl_in = 1
            1: 1,
        },
        'faucet-2': {
            # Port 4, acl_in = 2
            4: 2,
        },
        'faucet-3': {
            # Port 4, acl_in = 3
            4: 3,
        },
    }

    def setUp(self): # pylint: disable=invalid-name
        super(FaucetSingleStackAclControlTest, self).setUp()
        self.build_net(
            stack=True,
            n_dps=self.NUM_DPS,
            n_untagged=self.NUM_HOSTS,
            untagged_vid=self.VID,
            acls=self.ACLS,
            acl_in_dp=self.ACL_IN_DP,
            )
        self.start_net()

    def test_unicast(self):
        """Hosts in stack topology can appropriately reach each other over unicast."""
        hosts = self.net.hosts
        self.verify_tp_dst_notblocked(5000, hosts[0], hosts[1], table_id=None)
        self.verify_tp_dst_blocked(5000, hosts[0], hosts[3], table_id=None)
        self.verify_tp_dst_notblocked(5000, hosts[0], hosts[6], table_id=None)
        self.verify_tp_dst_blocked(5000, hosts[0], hosts[7], table_id=None)
        self.verify_no_cable_errors()

    def test_broadcast(self):
        """Hosts in stack topology can appropriately reach each other over broadcast."""
        hosts = self.net.hosts
        self.verify_bcast_dst_notblocked(5000, hosts[0], hosts[1])
        self.verify_bcast_dst_blocked(5000, hosts[0], hosts[3])
        self.verify_bcast_dst_notblocked(5000, hosts[0], hosts[6])
        self.verify_bcast_dst_blocked(5000, hosts[0], hosts[7])
        self.verify_no_cable_errors()


class FaucetStringOfDPACLOverrideTest(FaucetStringOfDPTest):

    NUM_DPS = 1
    NUM_HOSTS = 2

    # ACL rules which will get overridden.
    ACLS = {
        1: [
            {'rule': {
                'dl_type': int('0x800', 16),
                'ip_proto': 6,
                'tcp_dst': 5001,
                'actions': {
                    'allow': 1,
                },
            }},
            {'rule': {
                'dl_type': int('0x800', 16),
                'ip_proto': 6,
                'tcp_dst': 5002,
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
                'ip_proto': 6,
                'tcp_dst': 5001,
                'actions': {
                    'allow': 0,
                },
            }},
            {'rule': {
                'dl_type': int('0x800', 16),
                'ip_proto': 6,
                'tcp_dst': 5002,
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

    def setUp(self): # pylint: disable=invalid-name
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
        with open(self.acls_config, 'w') as config_file:
            config_file.write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_no_cable_errors()

    def test_port5002_notblocked(self):
        """Test that TCP port 5002 is not blocked."""
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[0:2]
        self.verify_tp_dst_blocked(5002, first_host, second_host)
        with open(self.acls_config, 'w') as config_file:
            config_file.write(self.get_config(acls=self.ACLS_OVERRIDE))
        self.verify_faucet_reconf(cold_start=False, change_expected=True)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)
        self.verify_no_cable_errors()


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
                table_id=self._FLOOD_TABLE))


class FaucetTaggedGroupTableTest(FaucetTaggedTest):

    CONFIG = """
        group_table: True
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

    def test_group_exist(self):
        self.assertEqual(
            100,
            self.get_group_id_for_matching_flow(
                {u'dl_vlan': u'100', u'dl_dst': u'ff:ff:ff:ff:ff:ff'},
                table_id=self._FLOOD_TABLE))


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
"""
    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        group_table_routing: True
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
        for _ in range(2):
            self.verify_ipv4_routing(
                first_host, first_host_routed_ip,
                second_host, second_host_routed_ip,
                with_group_table=True)
            self.swap_host_macs(first_host, second_host)


class FaucetGroupTableUntaggedIPv6RouteTest(FaucetUntaggedTest):

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
"""

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        group_table_routing: True
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
        for _ in range(2):
            self.verify_ipv6_routing_pair(
                first_host, first_host_ip, first_host_routed_ip,
                second_host, second_host_ip, second_host_routed_ip,
                with_group_table=True)
            self.swap_host_macs(first_host, second_host)


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
        self.retry_net_ping(hosts=(first_host, second_host))
        self.wait_nonzero_packet_count_flow(
            {u'dl_src': u'0e:0d:00:00:00:00/ff:ff:00:00:00:00'},
            table_id=self._PORT_ACL_TABLE)


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
                    set_fields:
                        - eth_dst: "00:00:00:00:00:03"
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
            table_id=self._ETH_DST_TABLE,
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


@unittest2.skip('use_idle_timeout unreliable')
class FaucetWithUseIdleTimeoutTest(FaucetUntaggedTest):
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""
    CONFIG = """
        timeout: 1
        use_idle_timeout: true
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

    def wait_for_host_removed(self, host, in_port, timeout=5):
        for _ in range(timeout):
            if not self.host_learned(host, in_port=in_port, timeout=1):
                return
        self.fail('host %s still learned' % host)

    def wait_for_flowremoved_msg(self, src_mac=None, dst_mac=None, timeout=30):
        pattern = "OFPFlowRemoved"
        mac = None
        if src_mac:
            pattern = "OFPFlowRemoved(.*)'eth_src': '%s'" % src_mac
            mac = src_mac
        if dst_mac:
            pattern = "OFPFlowRemoved(.*)'eth_dst': '%s'" % dst_mac
            mac = dst_mac
        for _ in range(timeout):
            for _, debug_log_name in self._get_ofchannel_logs():
                with open(debug_log_name) as debug_log:
                    debug = debug_log.read()
                if re.search(pattern, debug):
                    return
            time.sleep(1)
        self.fail('Not received OFPFlowRemoved for host %s' % mac)

    def wait_for_host_log_msg(self, host_mac, msg, timeout=15):
        controller = self._get_controller()
        count = 0
        for _ in range(timeout):
            count = controller.cmd('grep -c "%s %s" %s' % (
                msg, host_mac, self.env['faucet']['FAUCET_LOG']))
            if int(count) != 0:
                break
            time.sleep(1)
        self.assertGreaterEqual(
            int(count), 1, 'log msg "%s" for host %s not found' % (msg, host_mac))

    def test_untagged(self):
        self.ping_all_when_learned()
        first_host, second_host = self.net.hosts[:2]
        self.swap_host_macs(first_host, second_host)
        for host, port in (
                (first_host, self.port_map['port_1']),
                (second_host, self.port_map['port_2'])):
            self.wait_for_flowremoved_msg(src_mac=host.MAC())
            self.require_host_learned(host, in_port=int(port))


@unittest2.skip('use_idle_timeout unreliable')
class FaucetWithUseIdleTimeoutRuleExpiredTest(FaucetWithUseIdleTimeoutTest):

    def test_untagged(self):
        """Host that is actively sending should have its dst rule renewed as the
        rule expires. Host that is not sending expires as usual.
        """
        self.ping_all_when_learned()
        first_host, second_host, third_host, fourth_host = self.net.hosts
        self.host_ipv4_alias(first_host, ipaddress.ip_interface(u'10.99.99.1/24'))
        first_host.cmd('arp -s %s %s' % (second_host.IP(), second_host.MAC()))
        first_host.cmd('timeout 120s ping -I 10.99.99.1 %s &' % second_host.IP())
        for host in (second_host, third_host, fourth_host):
            self.host_drop_all_ips(host)
        self.wait_for_host_log_msg(first_host.MAC(), 'refreshing host')
        self.assertTrue(self.host_learned(
            first_host, in_port=int(self.port_map['port_1'])))
        for host, port in (
                (second_host, self.port_map['port_2']),
                (third_host, self.port_map['port_3']),
                (fourth_host, self.port_map['port_4'])):
            self.wait_for_flowremoved_msg(src_mac=host.MAC())
            self.wait_for_host_log_msg(host.MAC(), 'expiring host')
            self.wait_for_host_removed(host, in_port=int(port))
