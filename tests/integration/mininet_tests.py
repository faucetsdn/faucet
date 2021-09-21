#!/usr/bin/env python3

"""Mininet tests for FAUCET."""

# pylint: disable=too-many-lines
# pylint: disable=missing-class-docstring,missing-function-docstring
# pylint: disable=too-many-arguments

import binascii
import collections
import copy
import itertools
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import threading
import time
import unittest

from http.server import SimpleHTTPRequestHandler
from http.server import HTTPServer

import scapy.all

import yaml  # pytype: disable=pyi-error

from mininet.log import error
from mininet.util import pmonitor

from clib import mininet_test_base
from clib import mininet_test_util

from clib.mininet_test_base import PEER_BGP_AS, IPV4_ETH, IPV6_ETH

MIN_MBPS = 100


CONFIG_BOILER_UNTAGGED = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

CONFIG_TAGGED_BOILER = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                count_untag_vlan_miss: true
            %(port_2)d:
                tagged_vlans: [100]
                count_untag_vlan_miss: true
            %(port_3)d:
                tagged_vlans: [100]
                count_untag_vlan_miss: true
            %(port_4)d:
                tagged_vlans: [100]
                count_untag_vlan_miss: true
"""


class QuietHTTPServer(HTTPServer):

    allow_reuse_address = True
    timeout = None

    @staticmethod
    def handle_error(_request, _client_address):
        return


class PostHandler(SimpleHTTPRequestHandler):

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        return

    def _log_post(self):
        content_len = int(self.headers.get('content-length', 0))
        content = self.rfile.read(content_len).decode().strip()
        if content and hasattr(self.server, 'influx_log'):
            with open(self.server.influx_log, 'a', encoding='utf-8') as influx_log:
                influx_log.write(content + '\n')


class InfluxPostHandler(PostHandler):

    def do_POST(self):  # pylint: disable=invalid-name
        self._log_post()
        return self.send_response(204)


class SlowInfluxPostHandler(PostHandler):

    def do_POST(self):  # pylint: disable=invalid-name
        self._log_post()
        time.sleep(self.server.timeout * 3)
        return self.send_response(500)


class FaucetTest(mininet_test_base.FaucetTestBase):

    pass


class FaucetUntaggedTest(FaucetTest):
    """Basic untagged VLAN test."""

    HOST_NAMESPACE = {}
    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
    EVENT_SOCK_HEARTBEAT = '5'
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    # pylint: disable=invalid-name
    CONFIG = CONFIG_BOILER_UNTAGGED

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid,
            host_namespace=self.HOST_NAMESPACE)
        self.start_net()

    def verify_events_log(self, event_log, timeout=10):
        required_events = {'CONFIG_CHANGE', 'PORT_CHANGE', 'L2_LEARN', 'PORTS_STATUS', 'EVENT_SOCK_HEARTBEAT'}
        for _ in range(timeout):
            prom_event_id = self.scrape_prometheus_var('faucet_event_id', dpid=False)
            event_id = None
            with open(event_log, 'r', encoding='utf-8') as event_log_file:
                for event_log_line in event_log_file.readlines():
                    event = json.loads(event_log_line.strip())
                    event_id = event['event_id']
                    required_events -= set(event.keys())
            if prom_event_id == event_id:
                return
            time.sleep(1)
        self.assertEqual(prom_event_id, event_id)
        self.assertFalse(required_events)

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        self._enable_event_log()
        self.ping_all_when_learned()
        self.flap_all_switch_ports()
        self.verify_traveling_dhcp_mac()
        self.gauge_smoke_test()
        self.prometheus_smoke_test()
        self.assertGreater(os.path.getsize(self.event_log), 0)
        self.verify_events_log(self.event_log)


class Faucet8021XBase(FaucetTest):

    NUM_FAUCET_CONTROLLERS = 1
    NUM_GAUGE_CONTROLLERS = 1

    HOST_NAMESPACE = {3: False}
    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1

    RADIUS_PORT = None

    DOT1X_EXPECTED_EVENTS = []
    SESSION_TIMEOUT = 3600
    LOG_LEVEL = 'DEBUG'

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        dot1x:
            nfv_intf: NFV_INTF
            nfv_sw_port: %(port_4)d
            radius_ip: 127.0.0.1
            radius_port: RADIUS_PORT
            radius_secret: SECRET
        interfaces:
            %(port_1)d:
                native_vlan: 100
                # 802.1x client.
                dot1x: True
            %(port_2)d:
                native_vlan: 100
                # 802.1X client.
                dot1x: True
            %(port_3)d:
                native_vlan: 100
                # ping host.
            %(port_4)d:
                output_only: True
                # "NFV host - interface used by controller."
"""

    wpasupplicant_conf_1 = """
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="user"
    password="microphone"
}
"""

    wpasupplicant_conf_2 = """
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="admin"
    password="megaphone"
}
    """

    freeradius_user_conf = """user   Cleartext-Password := "microphone"
    Session-timeout = {0}
admin  Cleartext-Password := "megaphone"
    Session-timeout = {0}
vlanuser1001  Cleartext-Password := "password"
    Tunnel-Type = "VLAN",
    Tunnel-Medium-Type = "IEEE-802",
    Tunnel-Private-Group-id = "radiusassignedvlan1"
vlanuser2222  Cleartext-Password := "milliphone"
    Tunnel-Type = "VLAN",
    Tunnel-Medium-Type = "IEEE-802",
    Tunnel-Private-Group-id = "radiusassignedvlan2"
filter_id_user_accept  Cleartext-Password := "accept_pass"
    Filter-Id = "accept_acl"
filter_id_user_deny  Cleartext-Password := "deny_pass"
    Filter-Id = "deny_acl"
"""

    eapol1_host = None
    eapol2_host = None
    ping_host = None
    nfv_host = None
    nfv_intf = None
    nfv_portno = None

    @staticmethod
    def _priv_mac(host_id):
        two_byte_port_num = '%04x' % host_id
        two_byte_port_num_formatted = ':'.join((two_byte_port_num[:2], two_byte_port_num[2:]))
        return f'00:00:00:00:{two_byte_port_num_formatted}'

    def pre_start_net(self):
        self.eapol1_host, self.eapol2_host, self.ping_host, self.nfv_host = self.hosts_name_ordered()
        switch = self.first_switch()
        last_host_switch_link = switch.connectionsTo(self.nfv_host)[0]
        nfv_intf = [
            intf for intf in last_host_switch_link if intf in switch.intfList()][0]
        self.nfv_intf = str(nfv_intf)
        nfv_intf = self.nfv_host.intf()

        self.RADIUS_PORT = mininet_test_util.find_free_udp_port(self.ports_sock, self._test_name())

        self.CONFIG = self.CONFIG.replace('NFV_INTF', str(nfv_intf))
        self.CONFIG = self.CONFIG.replace('RADIUS_PORT', str(self.RADIUS_PORT))
        super()._init_faucet_config()

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid,
            host_namespace=self.HOST_NAMESPACE)
        self.start_net()

        self.nfv_portno = self.port_map['port_4']

        self.host_drop_all_ips(self.nfv_host)
        self.nfv_pids = []

        tcpdump_args = '-e -n -U'
        self.eapol1_host.cmd(
            mininet_test_util.timeout_cmd(
                'tcpdump -w %s/%s-start.pcap %s ether proto 0x888e &' % (
                    self.tmpdir, self.eapol1_host.name, tcpdump_args), 300))

        self.nfv_host.cmd(
            mininet_test_util.timeout_cmd(
                'tcpdump -i %s-eth0 -w %s/eap-lo.pcap %s ether proto 0x888e &' % (
                    self.nfv_host.name, self.tmpdir, tcpdump_args), 300))
        self.nfv_pids.append(int(self.nfv_host.lastPid))
        self.nfv_host.cmd(
            mininet_test_util.timeout_cmd(
                'tcpdump -i lo -w %s/radius.pcap %s udp port %d &' % (
                    self.tmpdir, tcpdump_args, self.RADIUS_PORT), 300))
        self.nfv_pids.append(int(self.nfv_host.lastPid))
        self.radius_log_path = self.start_freeradius()
        self.nfv_pids.append(int(self.nfv_host.lastPid))
        self._enable_event_log(300)

    def tearDown(self, ignore_oferrors=False):
        for pid in self.nfv_pids:
            self.nfv_host.cmd(f'kill {pid}')
        super().tearDown(ignore_oferrors=ignore_oferrors)

    def post_test_checks(self):
        self.assertGreater(os.path.getsize(self.event_log), 0)
        self.verify_dot1x_events_log()

    def verify_dot1x_events_log(self):

        def replace_mac(host_no):
            replacement_macs = {
                'HOST1_MAC': self.eapol1_host.MAC(),
                'HOST2_MAC': self.eapol2_host.MAC(),
                'HOST3_MAC': self.ping_host.MAC(),
                'HOST4_MAC': self.nfv_host.MAC(),
            }
            return replacement_macs.get(host_no, None)

        def insert_dynamic_values(dot1x_expected_events):
            for dot1x_event in dot1x_expected_events:
                top_level_key = list(dot1x_event.keys())[0]
                dot1x_params = {'dp_id': int(self.dpid)}
                for key, val in dot1x_event[top_level_key].items():
                    if key == 'port':
                        dot1x_params[key] = self.port_map[val]
                    elif key == 'eth_src':
                        dot1x_params[key] = replace_mac(val)
                dot1x_event[top_level_key].update(dot1x_params)

        if not self.DOT1X_EXPECTED_EVENTS:
            return

        dot1x_expected_events = copy.deepcopy(self.DOT1X_EXPECTED_EVENTS)
        insert_dynamic_values(dot1x_expected_events)

        with open(self.event_log, 'r', encoding='utf-8') as event_file:
            events_that_happened = []
            for event_log_line in event_file.readlines():
                if 'DOT1X' not in event_log_line:
                    continue
                event = json.loads(event_log_line.strip())
                events_that_happened.append(event['DOT1X'])

            for expected_event in dot1x_expected_events:
                self.assertTrue(expected_event in events_that_happened,
                                msg=f'expected event: {expected_event} not in '
                                    f'events_that_happened {events_that_happened}')

    @staticmethod
    def _eapol_filter(fields):
        return '(' + ' and '.join(('ether proto 0x888e',) + fields) + ')'

    def _success_eapol_filter(self, expect_success):
        eap_code = '0x04'
        if expect_success:
            eap_code = '0x03'
        return self._eapol_filter(('ether[14:4] == 0x01000004', f'ether[18] == {eap_code}'))

    def _logoff_eapol_filter(self):
        return self._eapol_filter(('ether[14:4] == 0x01020000',))

    def try_8021x(self, host, port_num, conf, and_logoff=False, terminate_wpasupplicant=False,
                  wpasup_timeout=180, tcpdump_timeout=30, expect_success=True):
        if expect_success:
            self.wait_8021x_flows(port_num)
        port_labels = self.port_labels(port_num)
        success_total = self.scrape_prometheus_var(
            'port_dot1x_success_total', labels=port_labels, default=0)
        failure_total = self.scrape_prometheus_var(
            'port_dot1x_failure_total', labels=port_labels, default=0)
        logoff_total = self.scrape_prometheus_var(
            'port_dot1x_logoff_total', labels=port_labels, default=0)
        dp_success_total = self.scrape_prometheus_var(
            'dp_dot1x_success_total', default=0)
        dp_failure_total = self.scrape_prometheus_var(
            'dp_dot1x_failure_total', default=0)
        dp_logoff_total = self.scrape_prometheus_var(
            'dp_dot1x_logoff_total', default=0)
        tcpdump_filters = [self._success_eapol_filter(expect_success)]
        if and_logoff:
            tcpdump_filters.append(self._logoff_eapol_filter())
        tcpdump_packets = len(tcpdump_filters)
        tcpdump_filter = ' or '.join(tcpdump_filters)
        tcpdump_txt = self.tcpdump_helper(
            host, tcpdump_filter, [
                lambda: self.wpa_supplicant_callback(
                    host, port_num, conf, and_logoff,
                    timeout=wpasup_timeout,
                    terminate_wpasupplicant=terminate_wpasupplicant)],
            timeout=tcpdump_timeout, vflags='-vvv', packets=tcpdump_packets)
        if expect_success:
            self.wait_for_eap_success(host, self.get_wpa_ctrl_path(host))
            if not and_logoff:
                self.wait_8021x_success_flows(host, port_num)
        success = 'Success' in tcpdump_txt
        if expect_success != success:
            return False
        new_success_total = self.scrape_prometheus_var(
            'port_dot1x_success_total', labels=port_labels, default=0)
        new_failure_total = self.scrape_prometheus_var(
            'port_dot1x_failure_total', labels=port_labels, default=0)
        new_logoff_total = self.scrape_prometheus_var(
            'port_dot1x_logoff_total', labels=port_labels, default=0)
        new_dp_success_total = self.scrape_prometheus_var(
            'dp_dot1x_success_total', default=0)
        new_dp_failure_total = self.scrape_prometheus_var(
            'dp_dot1x_failure_total', default=0)
        new_dp_logoff_total = self.scrape_prometheus_var(
            'dp_dot1x_logoff_total', default=0)
        if expect_success and success:
            self.assertGreater(new_success_total, success_total)
            self.assertGreater(new_dp_success_total, dp_success_total)
            self.assertEqual(failure_total, new_failure_total)
            self.assertEqual(dp_failure_total, new_dp_failure_total)
            logoff = 'logoff' in tcpdump_txt
            if logoff != and_logoff:
                return False
            if and_logoff:
                self.assertGreater(new_logoff_total, logoff_total)
            return True
        self.assertEqual(logoff_total, new_logoff_total)
        self.assertEqual(dp_logoff_total, new_dp_logoff_total)
        self.assertEqual(dp_success_total, new_dp_success_total)
        self.assertGreaterEqual(new_failure_total, failure_total)
        self.assertGreaterEqual(new_dp_failure_total, dp_failure_total)
        return False

    def retry_8021x(self, host, port_num, conf, and_logoff=False, retries=2, expect_success=True):
        for _ in range(retries):
            if self.try_8021x(host, port_num, conf, and_logoff, expect_success=expect_success):
                return True
            time.sleep(1)
        return False

    def wait_8021x_flows(self, port_no):
        port_actions = [
            'SET_FIELD: {eth_dst:%s}' % self._priv_mac(port_no), f'OUTPUT:{self.nfv_portno}']
        from_nfv_actions = [
            'SET_FIELD: {eth_src:01:80:c2:00:00:03}', f'OUTPUT:{port_no}']
        from_nfv_match = {
            'in_port': self.nfv_portno, 'dl_src': self._priv_mac(port_no), 'dl_type': 0x888e}
        self.wait_until_matching_flow(None, table_id=0, actions=port_actions)
        self.wait_until_matching_flow(from_nfv_match, table_id=0, actions=from_nfv_actions)

    def wait_8021x_success_flows(self, host, port_no):
        from_host_actions = [
            'GOTO_TABLE:1']
        from_host_match = {
            'in_port': port_no, 'dl_src': host.MAC()}
        self.wait_until_matching_flow(from_host_match, table_id=0, actions=from_host_actions)

    def verify_host_success(self, eapol_host, port_no, wpasupplicant_conf, and_logoff):
        self.one_ipv4_ping(
            eapol_host, self.ping_host.IP(), require_host_learned=False, expected_result=False)
        self.assertTrue(
            self.try_8021x(
                eapol_host, port_no, wpasupplicant_conf, and_logoff=and_logoff))
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(), require_host_learned=False, expected_result=True)

    def wpa_supplicant_callback(self, host, port_num, conf, and_logoff, timeout=10, terminate_wpasupplicant=False):
        wpa_ctrl_path = self.get_wpa_ctrl_path(host)
        if os.path.exists(wpa_ctrl_path):
            self.terminate_wpasupplicant(host)
            for pid in host.cmd(f'lsof -t {wpa_ctrl_path}').splitlines():
                try:
                    os.kill(int(pid), 15)
                except (ValueError, ProcessLookupError):
                    pass
            try:
                shutil.rmtree(wpa_ctrl_path)
            except FileNotFoundError:
                pass
        log_prefix = host.name + '_'
        self.start_wpasupplicant(
            host, conf, timeout=timeout,
            wpa_ctrl_socket_path=wpa_ctrl_path, log_prefix=log_prefix)
        if and_logoff:
            self.wait_for_eap_success(host, wpa_ctrl_path)
            self.wait_until_matching_flow(
                {'eth_src': host.MAC(), 'in_port': port_num}, table_id=0)
            self.one_ipv4_ping(
                host, self.ping_host.IP(), require_host_learned=False)
            host.cmd(f'wpa_cli -p {wpa_ctrl_path} logoff')
            self.wait_until_no_matching_flow(
                {'eth_src': host.MAC(), 'in_port': port_num}, table_id=0)
            self.one_ipv4_ping(
                host, self.ping_host.IP(),
                require_host_learned=False, expected_result=False)

        if terminate_wpasupplicant:
            self.terminate_wpasupplicant(host)

    def terminate_wpasupplicant(self, host):
        wpa_ctrl_path = self.get_wpa_ctrl_path(host)
        host.cmd(f'wpa_cli -p {wpa_ctrl_path} terminate')

    def get_wpa_ctrl_path(self, host):
        wpa_ctrl_path = os.path.join(
            self.tmpdir, f'{self.tmpdir}/{host.name}-wpasupplicant')
        return wpa_ctrl_path

    @staticmethod
    def get_wpa_status(host, wpa_ctrl_path):
        status = host.cmdPrint(f'wpa_cli -p {wpa_ctrl_path} status')
        for line in status.splitlines():
            if line.startswith('EAP state'):
                return line.split('=')[1].strip()
        return None

    def wait_for_eap_success(self, host, wpa_ctrl_path, timeout=5):
        for _ in range(timeout):
            eap_state = self.get_wpa_status(host, wpa_ctrl_path)
            if eap_state == 'SUCCESS':
                return
            time.sleep(1)
        self.fail(f'did not get EAP success: {eap_state}')

    def wait_for_radius(self, radius_log_path):
        self.wait_until_matching_lines_from_file(
            r'.*Ready to process requests', radius_log_path)

    def start_freeradius(self):
        radius_log_path = f'{self.tmpdir}/radius.log'

        listen_match = r'(listen {[^}]*(limit {[^}]*})[^}]*})|(listen {[^}]*})'
        listen_config = """listen {
        type = auth
        ipaddr = *
        port = %s
}
listen {
        type = acct
        ipaddr = *
        port = %d
}""" % (self.RADIUS_PORT, self.RADIUS_PORT + 1)

        if os.path.isfile('/etc/freeradius/users'):
            # Assume we are dealing with freeradius 2 configuration
            shutil.copytree('/etc/freeradius/', f'{self.tmpdir}/freeradius')
            users_path = f'{self.tmpdir}/freeradius/users'

            with open(f'{self.tmpdir}/freeradius/radiusd.conf', 'r+', encoding='utf-8') as default_site:
                default_config = default_site.read()
                default_config = re.sub(listen_match, '', default_config)
                default_site.seek(0)
                default_site.write(default_config)
                default_site.write(listen_config)
                default_site.truncate()
        else:
            # Assume we are dealing with freeradius >=3 configuration
            freerad_version = os.popen(
                r'freeradius -v | egrep -o -m 1 "Version ([0-9]\.[0.9])"').read().rstrip()
            freerad_major_version = freerad_version.split(' ')[1]
            shutil.copytree(f'/etc/freeradius/{freerad_major_version}/',
                            f'{self.tmpdir}/freeradius')
            users_path = f'{self.tmpdir}/freeradius/mods-config/files/authorize'

            with open(f'{self.tmpdir}/freeradius/sites-enabled/default', 'r+', encoding='utf-8') as default_site:
                default_config = default_site.read()
                default_config = re.sub(
                    listen_match, '', default_config)
                default_config = re.sub(
                    r'server default {', 'server default {\n' + listen_config, default_config)
                default_site.seek(0)
                default_site.write(default_config)
                default_site.truncate()

        with open(users_path, 'w', encoding='utf-8') as users_file:
            users_file.write(self.freeradius_user_conf.format(self.SESSION_TIMEOUT))

        with open(f'{self.tmpdir}/freeradius/clients.conf', 'w', encoding='utf-8') as clients:
            clients.write("""client localhost {
    ipaddr = 127.0.0.1
    secret = SECRET
}""")

        with open(f'{self.tmpdir}/freeradius/sites-enabled/inner-tunnel', 'r+', encoding='utf-8') as innertunnel_site:
            tunnel_config = innertunnel_site.read()
            listen_config = """listen {
       ipaddr = 127.0.0.1
       port = %d
       type = auth
}""" % (self.RADIUS_PORT + 2)
            tunnel_config = re.sub(listen_match, listen_config, tunnel_config)
            innertunnel_site.seek(0)
            innertunnel_site.write(tunnel_config)
            innertunnel_site.truncate()

        os.system(f'chmod o+rx {self.root_tmpdir}')
        os.system(f'chown -R root:freerad {self.tmpdir}/freeradius/')

        self.nfv_host.cmd(
            mininet_test_util.timeout_cmd(
                'freeradius -X -l %s -d %s/freeradius &' % (radius_log_path, self.tmpdir),
                300))

        self.wait_for_radius(radius_log_path)
        return radius_log_path


class Faucet8021XSuccessTest(Faucet8021XBase):

    DOT1X_EXPECTED_EVENTS = [
        {'ENABLED': {}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_2', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'success'}},
        {'AUTHENTICATION': {'port': 'port_2', 'eth_src': 'HOST2_MAC', 'status': 'success'}},
        {'AUTHENTICATION': {'port': 'port_2', 'eth_src': 'HOST2_MAC', 'status': 'logoff'}}]
    SESSION_TIMEOUT = 3600

    def test_untagged(self):
        self.verify_host_success(
            self.eapol1_host, self.port_map['port_1'], self.wpasupplicant_conf_1, False)
        self.verify_host_success(
            self.eapol2_host, self.port_map['port_2'], self.wpasupplicant_conf_1, True)
        self.post_test_checks()


class Faucet8021XFailureTest(Faucet8021XBase):
    """Failure due to incorrect identity/password"""

    wpasupplicant_conf_1 = """
    ap_scan=0
    network={
        key_mgmt=IEEE8021X
        eap=MD5
        identity="user"
        password="wrongpassword"
    }
    """

    DOT1X_EXPECTED_EVENTS = [
        {'ENABLED': {}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_2', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'failure'}}]

    def test_untagged(self):
        self.assertFalse(
            self.try_8021x(
                self.eapol1_host, self.port_map['port_1'],
                self.wpasupplicant_conf_1, and_logoff=False,
                expect_success=False))
        self.post_test_checks()


class Faucet8021XPortStatusTest(Faucet8021XBase):

    DOT1X_EXPECTED_EVENTS = [
        {'ENABLED': {}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_2', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'PORT_DOWN': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'PORT_DOWN': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'success'}},
        {'PORT_DOWN': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}}]

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        port_no2 = self.port_map['port_2']
        port_no4 = self.port_map['port_4']

        self.wait_8021x_flows(port_no1)
        self.set_port_down(port_no1)
        # self.wait_until_no_matching_flow(None, table_id=0, actions=actions)
        self.set_port_up(port_no1)
        self.wait_8021x_flows(port_no1)

        self.set_port_down(port_no4)
        # self.wait_until_no_matching_flow(match, table_id=0, actions=actions)
        self.set_port_up(port_no4)
        self.wait_8021x_flows(port_no1)

        # check only have rules for port 2 installed, after the NFV port comes up
        self.set_port_down(port_no1)
        self.flap_port(port_no4)
        self.wait_8021x_flows(port_no2)
        # no portno1

        self.set_port_up(port_no1)
        self.wait_8021x_flows(port_no1)

        # When the port goes down, and up the host should not be authenticated anymore.
        self.assertTrue(self.retry_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(), require_host_learned=False)

        # terminate so don't automatically reauthenticate when port goes back up.
        self.terminate_wpasupplicant(self.eapol1_host)

        self.flap_port(port_no1)
        self.wait_8021x_flows(port_no1)
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)
        self.post_test_checks()


class Faucet8021XPortFlapTest(Faucet8021XBase):

    def test_untagged(self):
        port_no1 = self.port_map['port_1']

        for _ in range(2):

            self.set_port_up(port_no1)
            self.assertTrue(self.retry_8021x(
                self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=True))

            self.set_port_down(port_no1)
            self.assertFalse(self.try_8021x(
                self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False, expect_success=False))
            self.one_ipv4_ping(
                self.eapol1_host, self.ping_host.IP(),
                require_host_learned=False, expected_result=False)
            wpa_status = self.get_wpa_status(
                self.eapol1_host, self.get_wpa_ctrl_path(self.eapol1_host))
            self.assertNotEqual('SUCCESS', wpa_status)
            # Kill supplicant so cant reply to the port up identity request.
            self.terminate_wpasupplicant(self.eapol1_host)

        self.post_test_checks()


class Faucet8021XIdentityOnPortUpTest(Faucet8021XBase):

    def test_untagged(self):
        port_no1 = self.port_map['port_1']

        # start wpa sup, logon, then send id request.
        self.set_port_up(port_no1)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))
        self.set_port_down(port_no1)
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)

        def port_up(port):
            self.set_port_up(port)
            self.wait_8021x_flows(port)

        username = 'user'
        username_bytes = ''.join(('%2x' % ord(c) for c in username))
        tcpdump_filter = ' or '.join((
            self._success_eapol_filter(True),
            self._eapol_filter((f'ether[23:4] == 0x{username_bytes}',))))
        tcpdump_txt = self.tcpdump_helper(
            self.eapol1_host, tcpdump_filter, [
                lambda: port_up(port_no1)],
            timeout=30, vflags='-vvv', packets=2)
        for req_str in (
                f'Identity: {username}',  # supplicant replies with username
                'Success',  # supplicant success
        ):
            self.assertTrue(req_str in tcpdump_txt, msg=f'{req_str} not in {tcpdump_txt}')

        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=True, retries=10)

        self.post_test_checks()


class Faucet8021XPeriodicReauthTest(Faucet8021XBase):

    SESSION_TIMEOUT = 15

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        port_labels1 = self.port_labels(port_no1)

        self.set_port_up(port_no1)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))

        last_total = self.scrape_prometheus_var(
            'port_dot1x_success_total', labels=port_labels1, default=0)
        for _ in range(4):
            for _ in range(self.SESSION_TIMEOUT * 2):
                total = self.scrape_prometheus_var(
                    'port_dot1x_success_total', labels=port_labels1, default=0)
                if total > last_total:
                    break
                time.sleep(1)
            self.assertGreater(total, last_total, msg='failed to successfully re-auth')
            last_total = total
        self.post_test_checks()


class Faucet8021XConfigReloadTest(Faucet8021XBase):

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        port_no2 = self.port_map['port_2']

        self.wait_8021x_flows(port_no1)
        self.wait_8021x_flows(port_no2)

        conf = self._get_faucet_conf()
        conf['dps'][self.DP_NAME]['interfaces'][port_no1]['dot1x'] = False

        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=True)

        self.wait_8021x_flows(port_no2)
        self.post_test_checks()


class Faucet8021XCustomACLLoginTest(Faucet8021XBase):
    """Ensure that 8021X Port ACLs Work before and after Login"""

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    auth_acl:
        - rule:
            dl_type: 0x800      # Allow ICMP / IPv4
            ip_proto: 1
            actions:
                allow: True
        - rule:
            dl_type: 0x0806     # ARP Packets
            actions:
                allow: True
    noauth_acl:
        - rule:
            dl_type: 0x800      # Deny ICMP / IPv4
            ip_proto: 1
            actions:
                allow: False
        - rule:
            dl_type: 0x0806     # ARP Packets
            actions:
                allow: True
    """

    CONFIG = """
        dot1x:
            nfv_intf: NFV_INTF
            nfv_sw_port: %(port_4)d
            radius_ip: 127.0.0.1
            radius_port: RADIUS_PORT
            radius_secret: SECRET
            auth_acl: auth_acl
            noauth_acl: noauth_acl
        interfaces:
            %(port_1)d:
                name: b1
                description: "b1"
                native_vlan: 100
                # 802.1x client.
                dot1x: True
                dot1x_acl: True
            %(port_2)d:
                name: b2
                description: "b2"
                native_vlan: 100
                # 802.1X client.
                dot1x: True
                dot1x_acl: True
            %(port_3)d:
                name: b3
                description: "b3"
                native_vlan: 100
                # ping host.
            %(port_4)d:
                name: b4
                description: "b4"
                output_only: True
                # "NFV host - interface used by controller."
    """

    def test_untagged(self):
        self.verify_host_success(
            self.eapol1_host, self.port_map['port_1'], self.wpasupplicant_conf_1, False)
        self.post_test_checks()


class Faucet8021XCustomACLLogoutTest(Faucet8021XCustomACLLoginTest):
    """Ensure that 8021X Port ACLs Work before and after Logout"""

    def test_untagged(self):
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, self.port_map['port_1'], self.wpasupplicant_conf_1, and_logoff=True))
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.post_test_checks()


class Faucet8021XMABTest(Faucet8021XSuccessTest):
    """Ensure that 802.1x Port Supports Mac Auth Bypass."""

    DOT1X_EXPECTED_EVENTS = [{'ENABLED': {}},
                             {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
                             {'PORT_UP': {'port': 'port_2', 'port_type': 'supplicant'}},
                             {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
                             {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC',
                                                 'status': 'success'}},
                             ]

    CONFIG = """
        dot1x:
            nfv_intf: NFV_INTF
            nfv_sw_port: %(port_4)d
            radius_ip: 127.0.0.1
            radius_port: RADIUS_PORT
            radius_secret: SECRET
        interfaces:
            %(port_1)d:
                native_vlan: 100
                # 802.1x client.
                dot1x: True
                dot1x_mab: True
            %(port_2)d:
                native_vlan: 100
                # 802.1X client.
                dot1x: True
            %(port_3)d:
                native_vlan: 100
                # ping host.
            %(port_4)d:
                output_only: True
                # "NFV host - interface used by controller."
    """

    def start_freeradius(self):
        # Add the host mac address to the FreeRADIUS config
        self.freeradius_user_conf += '\n{0}  Cleartext-Password := "{0}"'.format(
            str(self.eapol1_host.MAC()).replace(':', '')
        )
        return super().start_freeradius()

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)
        self.eapol1_host.run_dhclient(self.tmpdir)
        self.wait_until_matching_lines_from_faucet_log_files(r'.*AAA_SUCCESS.*')
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=True)
        self.assertEqual(
            1,
            self.scrape_prometheus_var('port_dot1x_success_total', labels=self.port_labels(port_no1), default=0))
        self.post_test_checks()


class Faucet8021XDynACLLoginTest(Faucet8021XCustomACLLoginTest):
    """Ensure that 8021X Port ACLs Work before and after Logout"""
    DOT1X_EXPECTED_EVENTS = [
        {'ENABLED': {}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_2', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'success'}},
        {'AUTHENTICATION': {'port': 'port_2', 'eth_src': 'HOST2_MAC', 'status': 'success'}},
    ]

    wpasupplicant_conf_1 = """
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="filter_id_user_accept"
    password="accept_pass"
}
       """
    wpasupplicant_conf_2 = """
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eap=MD5
    identity="filter_id_user_deny"
    password="deny_pass"
}
        """

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
acls:
    accept_acl:
        dot1x_assigned: True
        rules:
        - rule:
            dl_type: 0x800      # Allow ICMP / IPv4
            ip_proto: 1
            actions:
                allow: True
        - rule:
            dl_type: 0x0806     # ARP Packets
            actions:
                allow: True
    deny_acl:
        dot1x_assigned: True
        rules:
        - rule:
            dl_type: 0x800      # Deny ICMP / IPv4
            ip_proto: 1
            actions:
                allow: False
        - rule:
            dl_type: 0x0806     # ARP Packets
            actions:
                allow: True
            """

    CONFIG = """
        dot1x:
           nfv_intf: NFV_INTF
           nfv_sw_port: %(port_4)d
           radius_ip: 127.0.0.1
           radius_port: RADIUS_PORT
           radius_secret: SECRET
        interfaces:
           %(port_1)d:
               name: b1
               description: "b1"
               native_vlan: 100
               # 802.1x client.
               dot1x: True
               dot1x_dyn_acl: True
           %(port_2)d:
               name: b2
               description: "b2"
               native_vlan: 100
               # 802.1X client.
               dot1x: True
               dot1x_dyn_acl: True
           %(port_3)d:
               name: b3
               description: "b3"
               native_vlan: 100
               # ping host.
           %(port_4)d:
               name: b4
               description: "b4"
               output_only: True
               # "NFV host - interface used by controller."
           """

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        port_no2 = self.port_map['port_2']

        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.one_ipv4_ping(self.eapol2_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))
        self.assertTrue(self.try_8021x(
            self.eapol2_host, port_no2, self.wpasupplicant_conf_2, and_logoff=False))
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=True)
        self.one_ipv4_ping(self.eapol2_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.post_test_checks()


class Faucet8021XDynACLLogoutTest(Faucet8021XDynACLLoginTest):

    DOT1X_EXPECTED_EVENTS = [
        {'ENABLED': {}},
        {'PORT_UP': {'port': 'port_1', 'port_type': 'supplicant'}},
        {'PORT_UP': {'port': 'port_4', 'port_type': 'nfv'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'success'}},
        {'AUTHENTICATION': {'port': 'port_1', 'eth_src': 'HOST1_MAC', 'status': 'logoff'}}
    ]

    def test_untagged(self):
        port_no1 = self.port_map['port_1']
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=True))
        self.one_ipv4_ping(self.eapol1_host, self.ping_host.IP(),
                           require_host_learned=False, expected_result=False)
        self.post_test_checks()


class Faucet8021XVLANTest(Faucet8021XSuccessTest):
    """Test that two hosts are put into vlans.
    Same VLAN, Logoff, diff VLANs, port flap."""

    CONFIG_GLOBAL = """vlans:
        100:
            vid: 100
            description: "untagged"
        radiusassignedvlan1:
            vid: %u
            description: "untagged"
            dot1x_assigned: True
        radiusassignedvlan2:
            vid: %u
            description: "untagged"
            dot1x_assigned: True
    """ % (mininet_test_base.MAX_TEST_VID - 1,
           mininet_test_base.MAX_TEST_VID)

    CONFIG = """
        dot1x:
            nfv_intf: NFV_INTF
            nfv_sw_port: %(port_4)d
            radius_ip: 127.0.0.1
            radius_port: RADIUS_PORT
            radius_secret: SECRET
        interfaces:
            %(port_1)d:
                native_vlan: 100
                # 802.1x client.
                dot1x: True
            %(port_2)d:
                native_vlan: 100
                # 802.1X client.
                dot1x: True
            %(port_3)d:
                native_vlan: radiusassignedvlan1
                # ping host.
            %(port_4)d:
                output_only: True
                # "NFV host - interface used by controller."
    """

    RADIUS_PORT = 1940
    DOT1X_EXPECTED_EVENTS = []

    wpasupplicant_conf_1 = """
    ap_scan=0
    network={
        key_mgmt=IEEE8021X
        eap=MD5
        identity="vlanuser1001"
        password="password"
    }
    """

    wpasupplicant_conf_2 = """
    ap_scan=0
    network={
        key_mgmt=IEEE8021X
        eap=MD5
        identity="vlanuser2222"
        password="milliphone"
    }
    """

    def test_untagged(self):
        vid = 100 ^ mininet_test_base.OFPVID_PRESENT
        radius_vid1 = (mininet_test_base.MAX_TEST_VID - 1) ^ mininet_test_base.OFPVID_PRESENT
        radius_vid2 = mininet_test_base.MAX_TEST_VID ^ mininet_test_base.OFPVID_PRESENT
        port_no1 = self.port_map['port_1']
        port_no2 = self.port_map['port_2']
        port_no3 = self.port_map['port_3']
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))

        self.wait_until_matching_flow(
            {'in_port': port_no1},
            table_id=self._VLAN_TABLE,
            actions=['SET_FIELD: {vlan_vid:%u}' % radius_vid1])
        self.wait_until_matching_flow(
            {'vlan_vid': radius_vid1},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no1}', f'OUTPUT:{port_no3}'])
        self.wait_until_matching_flow(
            {'vlan_vid': vid},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no2}'])
        self.wait_until_no_matching_flow(
            {'vlan_vid': radius_vid2},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no1}', f'OUTPUT:{port_no2}'])

        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=True)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=True))
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)

        # check ports are back in the right vlans.
        self.wait_until_no_matching_flow(
            {'in_port': port_no1},
            table_id=self._VLAN_TABLE,
            actions=['SET_FIELD: {vlan_vid:%u}' % radius_vid1])
        self.wait_until_matching_flow(
            {'in_port': port_no1},
            table_id=self._VLAN_TABLE,
            actions=['SET_FIELD: {vlan_vid:%u}' % vid])

        # check flood ports are in the right vlans
        self.wait_until_no_matching_flow(
            {'vlan_vid': radius_vid1},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no1}', f'OUTPUT:{port_no2}'])
        self.wait_until_matching_flow(
            {'vlan_vid': vid},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no1}', f'OUTPUT:{port_no2}'])

        # check two 1x hosts play nicely. (same dyn vlan)
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_1, and_logoff=False))
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=True)
        self.one_ipv4_ping(
            self.eapol1_host, self.eapol2_host.IP(),
            require_host_learned=False, expected_result=False)
        self.assertTrue(self.try_8021x(
            self.eapol2_host, port_no2, self.wpasupplicant_conf_1, and_logoff=False))
        self.one_ipv4_ping(
            self.eapol2_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=True)
        self.one_ipv4_ping(
            self.eapol2_host, self.eapol1_host.IP(),
            require_host_learned=False, expected_result=True)

        # check two 1x hosts dont play (diff dyn vlan).
        self.assertTrue(self.try_8021x(
            self.eapol2_host, port_no2, self.wpasupplicant_conf_2, and_logoff=False))
        self.one_ipv4_ping(
            self.eapol2_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)
        self.one_ipv4_ping(
            self.eapol2_host, self.eapol1_host.IP(),
            require_host_learned=False, expected_result=False)

        # move host1 to new VLAN
        self.assertTrue(self.try_8021x(
            self.eapol1_host, port_no1, self.wpasupplicant_conf_2, and_logoff=False))
        self.one_ipv4_ping(
            self.eapol1_host, self.ping_host.IP(),
            require_host_learned=False, expected_result=False)
        self.one_ipv4_ping(
            self.eapol1_host, self.eapol2_host.IP(),
            require_host_learned=False, expected_result=True)

        self.wait_until_matching_flow(
            {'eth_src': self.eapol1_host.MAC(), 'vlan_vid': radius_vid2},
            table_id=self._ETH_SRC_TABLE)
        self.wait_until_matching_flow(
            {'eth_src': self.eapol1_host.MAC(), 'vlan_vid': radius_vid2},
            table_id=self._ETH_SRC_TABLE)
        self.wait_until_no_matching_flow(
            {'eth_src': self.eapol1_host.MAC(), 'vlan_vid': vid},
            table_id=self._ETH_SRC_TABLE)
        self.wait_until_no_matching_flow(
            {'eth_src': self.eapol1_host.MAC(), 'vlan_vid': radius_vid1},
            table_id=self._ETH_SRC_TABLE)
        self.wait_until_no_matching_flow(
            {'eth_dst': self.eapol1_host.MAC(), 'vlan_vid': vid},
            table_id=self._ETH_DST_TABLE)
        self.wait_until_no_matching_flow(
            {'eth_dst': self.eapol1_host.MAC(), 'vlan_vid': radius_vid1},
            table_id=self._ETH_DST_TABLE)

        # test port up/down. removes the dynamic vlan & host cache.
        self.flap_port(port_no2)

        self.wait_until_matching_flow(
            {'in_port': port_no2},
            table_id=self._VLAN_TABLE,
            actions=['SET_FIELD: {vlan_vid:%u}' % vid])
        self.wait_until_matching_flow(
            {'vlan_vid': vid},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no2}'])
        self.wait_until_no_matching_flow(
            {'in_port': port_no2},
            table_id=self._VLAN_TABLE,
            actions=['SET_FIELD: {vlan_vid:%u}' % radius_vid2])
        self.wait_until_no_matching_flow(
            {'vlan_vid': radius_vid2},
            table_id=self._FLOOD_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no1}', f'OUTPUT:{port_no2}'])
        self.wait_until_no_matching_flow(
            {'eth_src': self.eapol2_host.MAC()},
            table_id=self._ETH_SRC_TABLE)
        self.wait_until_no_matching_flow(
            {'eth_dst': self.eapol2_host.MAC(), 'vlan_vid': radius_vid1},
            table_id=self._ETH_DST_TABLE,
            actions=['POP_VLAN', f'OUTPUT:{port_no2}'])

        self.post_test_checks()


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
            %(port_2)d:
                native_vlan: randvlan
            %(port_3)d:
                native_vlan: randvlan
            %(port_4)d:
                native_vlan: randvlan
"""

    def test_untagged(self):
        last_vid = None
        for _ in range(5):
            vid = random.randint(2, mininet_test_base.MAX_TEST_VID)
            if vid == last_vid:
                continue
            self.change_vlan_config(
                'randvlan', 'vid', vid, cold_start=True, hup=True)
            self.ping_all_when_learned()
            last_vid = vid


class FaucetUntaggedNoCombinatorialFloodTest(FaucetUntaggedTest):

    CONFIG = """
        combinatorial_port_flood: False
""" + CONFIG_BOILER_UNTAGGED


class FaucetUntaggedControllerNfvTest(FaucetUntaggedTest):

    def test_untagged(self):
        # Name of switch interface connected to last host,
        #  accessible to controller
        last_host = self.hosts_name_ordered()[-1]
        switch = self.first_switch()
        last_host_switch_link = switch.connectionsTo(last_host)[0]
        last_host_switch_intf = [intf for intf in last_host_switch_link if intf in switch.intfList()][0]

        super().test_untagged()

        # Confirm controller can see switch interface with traffic.
        ifconfig_output = self.net.controllers[0].cmd(f'ifconfig {last_host_switch_intf}')
        self.assertTrue(
            re.search('(R|T)X packets[: ][1-9]', ifconfig_output),
            msg=ifconfig_output)


class FaucetUntaggedBroadcastTest(FaucetUntaggedTest):

    def test_untagged(self):
        super().test_untagged()
        self.verify_broadcast()
        self.verify_no_bcast_to_self()
        self.verify_unicast_not_looped()


class FaucetUntaggedNSLoopTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
acls:
    nsonly:
        - rule:
            dl_type: %u
            ip_proto: 58
            icmpv6_type: 135
            actions:
                allow: 1
        - rule:
            actions:
                allow: 0
vlans:
    100:
        description: "untagged"
""" % IPV6_ETH

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: nsonly
            %(port_2)d:
                native_vlan: 100
                acl_in: nsonly
            %(port_3)d:
                native_vlan: 100
                acl_in: nsonly
            %(port_4)d:
                native_vlan: 100
                acl_in: nsonly
    """

    def test_untagged(self):
        self.verify_no_bcast_to_self()


class FaucetUntaggedNoCombinatorialBroadcastTest(FaucetUntaggedBroadcastTest):

    CONFIG = """
        combinatorial_port_flood: False
""" + CONFIG_BOILER_UNTAGGED


class FaucetUntaggedLogRotateTest(FaucetUntaggedTest):

    def test_untagged(self):
        faucet_log = self.env[self.faucet_controllers[0].name]['FAUCET_LOG']
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
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    @staticmethod
    def wireshark_payload_format(payload_str):
        formatted_payload_str = ''
        groupsize = 4
        for payload_offset in range(len(payload_str) // groupsize):
            char_count = payload_offset * 2
            if char_count % 0x10 == 0:
                formatted_payload_str += '0x%4.4x: ' % char_count
            payload_fragment = payload_str[payload_offset * groupsize:][:groupsize]
            formatted_payload_str += ' ' + payload_fragment
        return formatted_payload_str

    def test_untagged(self):
        first_host = self.hosts_name_ordered()[0]
        tcpdump_filter = 'ether proto 0x88cc'
        timeout = 5 * 3
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd(f'sleep {timeout}')],
            timeout=timeout, vflags='-vv', packets=1)
        oui_prefix = ''.join(self.FAUCET_MAC.split(':')[:3])
        faucet_lldp_dp_id_attr = '%2.2x' % 1
        expected_lldp_dp_id = ''.join((
            oui_prefix,
            faucet_lldp_dp_id_attr,
            binascii.hexlify(str(self.dpid).encode('UTF-8')).decode()))
        for lldp_required in (
                r'%s > 01:80:c2:00:00:0e, ethertype LLDP' % self.FAUCET_MAC,
                r'Application type \[voice\] \(0x01\), Flags \[Tagged\]Vlan id 50',
                r'System Name TLV \(5\), length 6: faucet',
                r'Port Description TLV \(4\), length 10: first_port',
                self.wireshark_payload_format(expected_lldp_dp_id)):
            self.assertTrue(
                re.search(lldp_required, tcpdump_txt),
                msg='%s: %s' % (lldp_required, tcpdump_txt))


class FaucetLLDPIntervalTest(FaucetUntaggedTest):

    NUM_FAUCET_CONTROLLERS = 1

    CONFIG = """
        lldp_beacon:
            send_interval: 10
            max_per_interval: 5
        interfaces:
            %(port_1)d:
                native_vlan: 100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host = self.hosts_name_ordered()[0]
        tcpdump_filter = 'ether proto 0x88cc'
        interval = 10
        timeout = interval * 3
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd(f'sleep {timeout}')],
            # output epoch secs
            timeout=timeout, vflags='-tt', packets=2)
        timestamps = re.findall(r'(\d+)\.\d+ [0-9a-f:]+ \> [0-9a-f:]+', tcpdump_txt)
        timestamps = [int(timestamp) for timestamp in timestamps]
        self.assertTrue(timestamps[1] - timestamps[0] >= interval, msg=tcpdump_txt)


class FaucetUntaggedLLDPDefaultFallbackTest(FaucetUntaggedTest):

    CONFIG = """
        lldp_beacon:
            send_interval: 5
            max_per_interval: 5
        interfaces:
            %(port_1)d:
                native_vlan: 100
                lldp_beacon:
                    enable: True
                    org_tlvs:
                        - {oui: 0x12bb, subtype: 2, info: "01406500"}
"""

    def test_untagged(self):
        first_host = self.hosts_name_ordered()[0]
        tcpdump_filter = 'ether proto 0x88cc'
        timeout = 5 * 3
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd(f'sleep {timeout}')],
            timeout=timeout, vflags='-vv', packets=1)
        for lldp_required in (
                r'%s > 01:80:c2:00:00:0e, ethertype LLDP' % self.FAUCET_MAC,
                r'Application type \[voice\] \(0x01\), Flags \[Tagged\]Vlan id 50',
                r'System Name TLV \(5\), length 8: faucet-1',
                r'Port Description TLV \(4\), length [1-9]: b%u' % self.port_map['port_1']):
            self.assertTrue(
                re.search(lldp_required, tcpdump_txt),
                msg=f'{lldp_required}: {tcpdump_txt}')


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

    def get_gauge_watcher_config(self):
        return """
    port_stats:
        dps: ['%s']
        type: 'port_stats'
        interval: 5
        db: 'stats_file'
    port_state:
        dps: ['%s']
        type: 'port_state'
        interval: 5
        db: 'state_file'
    meter_stats:
        dps: ['%s']
        type: 'meter_stats'
        interval: 5
        db: 'meter_file'
    meter_stats_prom:
        dps: ['%s']
        type: 'meter_stats'
        db: 'prometheus'
        interval: 5
""" % (self.DP_NAME, self.DP_NAME, self.DP_NAME, self.DP_NAME)

    GAUGE_CONFIG_DBS = """
    prometheus:
        type: 'prometheus'
        prometheus_addr: '::1'
        prometheus_port: %(gauge_prom_port)d
"""
    config_ports = {'gauge_prom_port': None}

    def _get_gauge_meter_config(self, faucet_config_file,
                                monitor_stats_file,
                                monitor_state_file,
                                monitor_meter_stats_file):
        """Build Gauge Meter config."""
        return """
faucet_configs:
    - %s
watchers:
    %s
dbs:
    stats_file:
        type: 'text'
        file: %s
    state_file:
        type: 'text'
        file: %s
    meter_file:
        type: 'text'
        file: %s
%s
    """ % (faucet_config_file, self.get_gauge_watcher_config(),
           monitor_stats_file, monitor_state_file, monitor_meter_stats_file,
           self.GAUGE_CONFIG_DBS)

    def _init_gauge_config(self):
        gauge_config = self._get_gauge_meter_config(
            self.faucet_config_path,
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_meter_stats_file)
        if self.config_ports:
            gauge_config = gauge_config % self.config_ports
        self._write_yaml_conf(self.gauge_config_path, yaml.safe_load(gauge_config))

    def test_untagged(self):
        """All hosts on the same untagged VLAN should have connectivity."""
        # TODO: userspace DP port status not reliable.
        self.ping_all_when_learned()


class FaucetUntaggedApplyMeterTest(FaucetUntaggedMeterParseTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                acl_in: lossyacl
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        super().test_untagged()
        first_host, second_host = self.hosts_name_ordered()[:2]
        error('metered ping flood: %s' % first_host.cmd(
            'ping -c 1000 -f %s' % second_host.IP()))
        # Require meter band bytes to match.
        self.wait_until_matching_lines_from_file(
            r'.+faucet-1-1-byte-band-count.+[1-9].+',
            self.monitor_meter_stats_file)
        meter_labels = {
            'dp_id': self.dpid,
            'dp_name': self.DP_NAME,
            'meter_id': 1
        }
        byte_band_count = self.scrape_prometheus_var(
            'of_meter_byte_band_count', labels=meter_labels, controller=self.gauge_controller.name)
        self.assertTrue(byte_band_count)


class FaucetUntaggedMeterAddTest(FaucetUntaggedMeterParseTest):

    NUM_FAUCET_CONTROLLERS = 1

    def test_untagged(self):
        super().test_untagged()
        conf = self._get_faucet_conf()
        conf['meters']['lossymeter2'] = {
            'meter_id': 2,
            'entry': {
                'flags': ['PKTPS'],
                'bands': [{'rate': '1000', 'type': 'DROP'}]
            },
        }
        conf['acls']['lossyacl2'] = [{
            'rule': {
                'actions': {
                    'allow': 1,
                    'meter': 'lossymeter2'
                }
            }
        }]
        port_conf = conf['dps'][self.DP_NAME]['interfaces'][self.port_map['port_2']]
        port_conf['acls_in'] = ['lossyacl2']
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True, hup=True)
        self.wait_until_matching_lines_from_file(
            r'.+\'meter_id\'\: 2+',
            self.get_matching_meters_on_dpid(self.dpid))
        port_conf['acls_in'] = []
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True)
        self.wait_until_no_matching_lines_from_file(
            r'.+\'meter_id\'\: 2+',
            self.get_matching_meters_on_dpid(self.dpid))


class FaucetUntaggedMeterModTest(FaucetUntaggedMeterParseTest):

    def test_untagged(self):
        super().test_untagged()
        conf = self._get_faucet_conf()
        conf['dps'][self.DP_NAME]['interfaces'][self.port_map['port_1']]['acls_in'] = ['lossyacl']
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True, hup=True)
        self.wait_until_matching_lines_from_file(
            r'.+KBPS+',
            self.get_matching_meters_on_dpid(self.dpid))
        conf['meters']['lossymeter']['entry']['flags'] = ['PKTPS']
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=True, hup=True)
        self.wait_until_matching_lines_from_file(
            r'.+PKTPS+',
            self.get_matching_meters_on_dpid(self.dpid))


class FaucetUntaggedHairpinTest(FaucetUntaggedTest):

    NETNS = True
    CONFIG = """
        interfaces:
            %(port_1)d:
                hairpin: True
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        # Create macvlan interfaces, with one in a separate namespace,
        # to force traffic between them to be hairpinned via FAUCET.
        first_host, second_host = self.hosts_name_ordered()[:2]
        macvlan1_intf = 'macvlan1'
        macvlan1_ipv4 = '10.0.0.100'
        macvlan2_intf = 'macvlan2'
        macvlan2_ipv4 = '10.0.0.101'
        self.add_macvlan(first_host, macvlan1_intf, ipa=macvlan1_ipv4, mode='vepa')
        self.add_macvlan(first_host, macvlan2_intf, mode='vepa')
        macvlan2_mac = self.get_host_intf_mac(first_host, macvlan2_intf)
        netns = self.hostns(first_host)
        setup_cmds = []
        setup_cmds.extend(
            [f'ip link set {macvlan2_intf} netns {netns}'])
        for exec_cmd in (
                (f'ip address add {macvlan2_ipv4}/24 brd + dev {macvlan2_intf}',
                 f'ip link set {macvlan2_intf} up')):
            setup_cmds.append(f'ip netns exec {netns} {exec_cmd}')
        self.quiet_commands(first_host, setup_cmds)
        self.one_ipv4_ping(first_host, macvlan2_ipv4, intf=macvlan1_ipv4)
        self.one_ipv4_ping(first_host, second_host.IP())
        # Verify OUTPUT:IN_PORT flood rules are exercised.
        self.wait_nonzero_packet_count_flow(
            {'in_port': self.port_map['port_1'],
             'dl_dst': 'ff:ff:ff:ff:ff:ff'},
            table_id=self._FLOOD_TABLE, actions=['OUTPUT:IN_PORT'])
        self.wait_nonzero_packet_count_flow(
            {'in_port': self.port_map['port_1'],
             'dl_dst': macvlan2_mac},
            table_id=self._ETH_DST_HAIRPIN_TABLE, actions=['OUTPUT:IN_PORT'])


class FaucetUntaggedGroupHairpinTest(FaucetUntaggedHairpinTest):

    CONFIG = """
        group_table: True
        interfaces:
            %(port_1)d:
                hairpin: True
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
    """


class FaucetUntaggedTcpIPv4IperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host_ip = ipaddress.ip_address(first_host.IP())
        second_host_ip = ipaddress.ip_address(second_host.IP())
        for _ in range(3):
            self.ping_all_when_learned()
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                MIN_MBPS, first_host_ip, second_host_ip,
                sync_counters_func=lambda: self.one_ipv4_ping(first_host, second_host_ip))
            self.flap_all_switch_ports()


class FaucetUntaggedTcpIPv6IperfTest(FaucetUntaggedTest):

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host_ip = ipaddress.ip_interface('fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface('fc00::1:2/112')
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        for _ in range(3):
            self.ping_all_when_learned()
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                MIN_MBPS, first_host_ip.ip, second_host_ip.ip,
                sync_counters_func=lambda: self.one_ipv6_ping(first_host, second_host_ip.ip))
            self.flap_all_switch_ports()


class FaucetSanityTest(FaucetUntaggedTest):
    """Sanity test - make sure test environment is correct before running all tess."""

    def test_scapy_fuzz(self):
        # Scapy 2.4.5 has issues with 'fuzz' generation
        #  so black-list that version with a test
        exception = False
        try:
            scapy.all.send(scapy.all.fuzz(scapy.all.Ether()))  # pylint: disable=no-member
        except Exception as e:  # pylint: disable=broad-except
            error(f'{self._test_name()}:', e)
            exception = True
        self.assertFalse(exception, 'Scapy threw an exception in send(fuzz())')

    def test_ryu_config(self):
        varstr = ', '.join(self.scrape_prometheus(var='ryu_config'))
        self.assertTrue('echo_request_interval"} 10.0' in varstr)
        self.assertTrue('maximum_unreplied_echo_requests"} 5.0' in varstr)

    def verify_dp_port_healthy(self, dp_port, retries=5, min_mbps=MIN_MBPS):
        for _ in range(retries):
            port_desc = self.get_port_desc_from_dpid(self.dpid, dp_port)
            port_name = port_desc['name']
            port_state = port_desc['state']
            port_config = port_desc['config']
            port_speed_mbps = (port_desc['curr_speed'] * 1e3) / 1e6
            error(f'DP {dp_port} is {port_name}, at {port_speed_mbps} mbps\n')
            if port_speed_mbps < min_mbps:
                error(f'port speed {port_speed_mbps} below minimum {min_mbps} mbps\n')
            elif port_config != 0:
                error(f'port config {port_config} must be 0 (all clear)')
            elif port_state not in (0, 4):
                error(f'state {port_state} must be 0 (all flags clear or live)\n')
            else:
                return
            time.sleep(1)
        self.fail(f'DP port {dp_port} not healthy ({port_desc})')

    def test_portmap(self):
        prom_desc = self.scrape_prometheus(var='of_dp_desc_stats')
        self.assertIsNotNone(prom_desc, msg='Cannot scrape of_dp_desc_stats')
        error(f'DP: {prom_desc[0]}\n')
        error(f'port_map: {self.port_map}\n')
        for i, host in enumerate(self.hosts_name_ordered(), start=1):
            in_port = f'port_{i}'
            dp_port = self.port_map[in_port]
            if dp_port in self.switch_map:
                error(f'verifying cabling for {in_port}: host {self.switch_map[dp_port]} -> dp {dp_port}\n')
            else:
                error(f'verifying host {in_port} -> dp {dp_port}\n')
            self.verify_dp_port_healthy(dp_port)
            self.require_host_learned(host, in_port=dp_port)
        learned = self.prom_macs_learned()
        self.assertEqual(
            len(self.hosts_name_ordered()), len(learned),
            msg=f'test requires exactly {len(self.hosts_name_ordered())} hosts learned (got {learned})')

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

    def test_silence(self):
        # Make all test hosts silent and ensure we hear no other packets.
        for host in self.hosts_name_ordered():
            self.host_drop_all_ips(host)
            host.cmd('echo 1 > /proc/sys/net/ipv6/conf/%s/disable_ipv6' % host.defaultIntf())
        for host in self.hosts_name_ordered():
            tcpdump_filter = ''
            tcpdump_txt = self.tcpdump_helper(
                host, tcpdump_filter, [], timeout=10, vflags='-vv', packets=1)
            self.tcpdump_rx_packets(tcpdump_txt, 0)
            self.assertTrue(
                self.tcpdump_rx_packets(tcpdump_txt, 0),
                msg=f'got unexpected packet from test switch: {tcpdump_txt}')


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

    def test_untagged(self):
        self.wait_dp_status(1, controller=self.gauge_controller.name)
        self.assertIsNotNone(self.scrape_prometheus_var(
            'faucet_pbr_version', any_labels=True, controller=self.gauge_controller.name, retries=3))
        conf = self._get_faucet_conf()
        cookie = conf['dps'][self.DP_NAME]['cookie']

        if not self.wait_ports_updating(self.port_map.keys(), self.PORT_VARS):
            self.fail(msg='Gauge Prometheus port counters not increasing')

        for _ in range(self.DB_TIMEOUT * 3):
            updated_counters = True
            for host in self.hosts_name_ordered():
                host_labels = {
                    'dp_id': self.dpid,
                    'dp_name': self.DP_NAME,
                    'cookie': cookie,
                    'eth_dst': host.MAC(),
                    'inst_count': str(1),
                    'table_id': str(self._ETH_DST_TABLE),
                    'vlan': str(100),
                    'vlan_vid': str(4196)
                }
                packet_count = self.scrape_prometheus_var(
                    'flow_packet_count_eth_dst', labels=host_labels, controller=self.gauge_controller.name)
                byte_count = self.scrape_prometheus_var(
                    'flow_byte_count_eth_dst', labels=host_labels, controller=self.gauge_controller.name)
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

    def setUp(self):
        self.handler = InfluxPostHandler
        super().setUp()
        self.setup_influx()

    def tearDown(self, ignore_oferrors=False):
        if self.server:
            self.server.shutdown()
            self.server.socket.close()
        super().tearDown(ignore_oferrors=ignore_oferrors)

    def _wait_error_shipping(self, timeout=None):
        if timeout is None:
            timeout = self.DB_TIMEOUT * 3 * 2
        self.wait_until_matching_lines_from_gauge_log_files(
            r'.+error shipping.+', timeout=timeout)

    def _verify_influx_log(self, retries=3):
        self.assertTrue(os.path.exists(self.influx_log))
        expected_vars = {
            'dropped_in', 'dropped_out', 'bytes_out', 'flow_packet_count',
            'errors_in', 'errors_out', 'bytes_in', 'flow_byte_count',
            'port_state_reason', 'packets_in', 'packets_out'}

        observed_vars = set()
        for _ in range(retries):
            with open(self.influx_log, encoding='utf-8') as influx_log:
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
            if expected_vars == observed_vars:
                break
            time.sleep(1)

        self.assertEqual(expected_vars, observed_vars)
        self.verify_no_exception(self.env[self.gauge_controller.name]['GAUGE_EXCEPTION_LOG'])

    def _wait_influx_log(self):
        for _ in range(self.DB_TIMEOUT * 3):
            if os.path.exists(self.influx_log):
                return
            time.sleep(1)

    def _start_gauge_check(self):
        if self.server_thread:
            return None
        influx_port = self.config_ports['gauge_influx_port']
        try:
            self.server = QuietHTTPServer(
                (mininet_test_util.LOCALHOST, influx_port),
                self.handler)  # pytype: disable=attribute-error
            self.server.timeout = self.DB_TIMEOUT
            self.server_thread = threading.Thread(
                target=self.server.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            return None
        except socket.error as err:
            return f'cannot start Influx test server: {err}'

    def test_untagged(self):
        self.ping_all_when_learned()
        self.hup_controller(self.gauge_controller.name)
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

    @staticmethod
    def test_tagged():
        return

    def test_untagged(self):
        self.wait_dp_status(1, controller=self.gauge_controller.name)
        self.assertTrue(self.wait_ports_updating(self.port_map.keys(), self.PORT_VARS))
        self.ping_all_when_learned()
        self.hup_controller(controller=self.gauge_controller.name)
        self.flap_all_switch_ports()
        self._wait_influx_log()
        self._verify_influx_log()


class FaucetUntaggedInfluxDownTest(FaucetUntaggedInfluxTest):

    def _start_gauge_check(self):
        return None

    def test_untagged(self):
        self.ping_all_when_learned()
        self._wait_error_shipping()
        self.verify_no_exception(self.env[self.gauge_controller.name]['GAUGE_EXCEPTION_LOG'])


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
        self.verify_no_exception(self.env[self.gauge_controller.name]['GAUGE_EXCEPTION_LOG'])


class FaucetSingleUntaggedInfluxTooSlowTest(FaucetUntaggedInfluxTest):

    def setUp(self):
        self.handler = SlowInfluxPostHandler
        super().setUp()
        self.setup_influx()

    def test_untagged(self):
        self.ping_all_when_learned()
        self._wait_influx_log()
        self.assertTrue(os.path.exists(self.influx_log))
        self._wait_error_shipping()
        self.verify_no_exception(self.env[self.gauge_controller.name]['GAUGE_EXCEPTION_LOG'])


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
                    port: %(port_2)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    port: %(port_2)d
        - rule:
            actions:
                allow: 0
    2:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    port: %(port_1)d
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
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 2
            %(port_3)d:
                native_vlan: 100
                acl_in: 3
            %(port_4)d:
                native_vlan: 100
                acl_in: 4
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        first_host.setMAC('0e:00:00:00:01:01')
        second_host.setMAC('0e:00:00:00:02:02')
        self.one_ipv4_ping(
            first_host, second_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            second_host, first_host.IP(), require_host_learned=False)


class FaucetNailedForwardingOrderedTest(FaucetUntaggedTest):

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
                    - port: %(port_2)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    - port: %(port_2)d
        - rule:
            actions:
                allow: 0
    2:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    - port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    - port: %(port_1)d
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
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 2
            %(port_3)d:
                native_vlan: 100
                acl_in: 3
            %(port_4)d:
                native_vlan: 100
                acl_in: 4
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        first_host.setMAC('0e:00:00:00:01:01')
        second_host.setMAC('0e:00:00:00:02:02')
        self.one_ipv4_ping(
            first_host, second_host.IP(), require_host_learned=False)
        self.one_ipv4_ping(
            second_host, first_host.IP(), require_host_learned=False)


class FaucetNailedFailoverForwardingTest(FaucetNailedForwardingTest):

    NUM_FAUCET_CONTROLLERS = 1

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
                        ports: [%(port_2)d, %(port_3)d]
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    failover:
                        group_id: 1002
                        ports: [%(port_2)d, %(port_3)d]
        - rule:
            actions:
                allow: 0
    2:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    port: %(port_1)d
        - rule:
            actions:
                allow: 0
    3:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    port: %(port_1)d
        - rule:
            actions:
                allow: 0
    4:
        - rule:
            actions:
                allow: 0
"""

    def test_untagged(self):
        first_host, second_host, third_host = self.hosts_name_ordered()[0:3]
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


class FaucetNailedFailoverForwardingOrderedTest(FaucetNailedForwardingTest):

    NUM_FAUCET_CONTROLLERS = 1

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
                    - failover:
                        group_id: 1001
                        ports: [%(port_2)d, %(port_3)d]
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.2"
            actions:
                output:
                    - failover:
                        group_id: 1002
                        ports: [%(port_2)d, %(port_3)d]
        - rule:
            actions:
                allow: 0
    2:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    - port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    - port: %(port_1)d
        - rule:
            actions:
                allow: 0
    3:
        - rule:
            dl_dst: "0e:00:00:00:01:01"
            actions:
                output:
                    - port: %(port_1)d
        - rule:
            dl_type: 0x806
            dl_dst: "ff:ff:ff:ff:ff:ff"
            arp_tpa: "10.0.0.1"
            actions:
                output:
                    - port: %(port_1)d
        - rule:
            actions:
                allow: 0
    4:
        - rule:
            actions:
                allow: 0
"""

    def test_untagged(self):
        first_host, second_host, third_host = self.hosts_name_ordered()[0:3]
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
        self.verify_lldp_blocked()
        # Verify 802.1x flood block triggered.
        self.wait_nonzero_packet_count_flow(
            {'dl_dst': '01:80:c2:00:00:00/ff:ff:ff:ff:ff:f0'},
            table_id=self._FLOOD_TABLE)


class FaucetUntaggedCDPTest(FaucetUntaggedTest):

    def test_untagged(self):
        self.ping_all_when_learned()
        self.verify_cdp_blocked()


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
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def setUp(self):
        super().setUp()
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
        self.verify_no_bcast_to_self()


class FaucetTaggedAndUntaggedSameVlanEgressTest(FaucetTaggedAndUntaggedSameVlanTest):

    REQUIRES_METADATA = True
    CONFIG = """
        egress_pipeline: True
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""


class FaucetTaggedAndUntaggedSameVlanGroupTest(FaucetTaggedAndUntaggedSameVlanTest):

    CONFIG = """
        group_table: True
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""


class FaucetUntaggedMaxHostsTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        max_hosts: 2
"""

    CONFIG = CONFIG_BOILER_UNTAGGED

    def test_untagged(self):
        self.ping_all()
        learned_hosts = [
            host for host in self.hosts_name_ordered() if self.host_learned(host)]
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
            %(port_2)d:
                native_vlan: 100
                max_hosts: 3
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.ping_all_when_learned()
        for i in range(10, 10 + (self.MAX_HOSTS * 2)):
            mac_intf = f'mac{i}'
            mac_ipv4 = f'10.0.0.{i}'
            self.add_macvlan(second_host, mac_intf, ipa=mac_ipv4)
            ping_cmd = mininet_test_util.timeout_cmd(
                'fping %s -c1 -t1 -I%s %s > /dev/null 2> /dev/null' % (
                    self.FPING_ARGS_SHORT, mac_intf, first_host.IP()),
                2)
            second_host.cmd(ping_cmd)
        flows = self.get_matching_flows_on_dpid(
            self.dpid,
            {'dl_vlan': '100', 'in_port': int(self.port_map['port_2'])},
            table_id=self._ETH_SRC_TABLE)
        self.assertEqual(self.MAX_HOSTS, len(flows))
        port_labels = self.port_labels(self.port_map['port_2'])
        self.assertGreater(
            self.scrape_prometheus_var(
                'port_learn_bans', port_labels), 0)
        learned_macs = [
            mac for _, mac in self.scrape_prometheus_var(
                'learned_macs', dict(port_labels, vlan=100),
                multiple=True) if mac]
        self.assertEqual(self.MAX_HOSTS, len(learned_macs))


class FaucetSingleHostsTimeoutPrometheusTest(FaucetUntaggedTest):
    """Test that hosts learned and reported in Prometheus, time out."""

    TIMEOUT = 15
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        timeout: 25
        arp_neighbor_timeout: 12
        nd_neighbor_timeout: 12
        ignore_learn_ins: 0
        learn_jitter: 0
        cache_update_guard_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def hosts_learned(self, hosts):
        """Check that hosts are learned by FAUCET on the expected ports."""
        macs_learned = []
        for mac, port in hosts.items():
            if self.prom_mac_learned(mac, port=port):
                self.mac_learned(mac, in_port=port)
                macs_learned.append(mac)
        return macs_learned

    def verify_hosts_learned(self, first_host, second_host, mac_ips, hosts):
        mac_ipv4s = [mac_ipv4 for mac_ipv4, _ in mac_ips]
        fping_cmd = mininet_test_util.timeout_cmd(
            'fping %s -c%u %s' % (
                self.FPING_ARGS_SHORT, int(self.TIMEOUT / 3), ' '.join(mac_ipv4s)),
            self.TIMEOUT / 2)
        for _ in range(3):
            fping_out = first_host.cmd(fping_cmd)
            self.assertTrue(fping_out, msg=f'fping did not complete: {fping_cmd}')
            macs_learned = self.hosts_learned(hosts)
            if len(macs_learned) == len(hosts):
                return
            time.sleep(1)
        first_host_diag = first_host.cmd('ifconfig -a ; arp -an')
        second_host_diag = second_host.cmd('ifconfig -a ; arp -an')
        self.fail(f'{mac_ips} cannot be learned ({macs_learned} != {fping_out})\n'
                  f'first host {first_host_diag}\nsecond host {second_host_diag}\n')

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        all_learned_mac_ports = {}

        # learn batches of hosts, then down them
        for base in (10, 20, 30):
            def add_macvlans(base, count):
                mac_intfs = []
                mac_ips = []
                learned_mac_ports = {}
                for i in range(base, base + count):
                    mac_intf = f'mac{i}'
                    mac_intfs.append(mac_intf)
                    mac_ipv4 = f'10.0.0.{i}'
                    self.add_macvlan(second_host, mac_intf, ipa=mac_ipv4)
                    macvlan_mac = self.get_mac_of_intf(mac_intf, second_host)
                    learned_mac_ports[macvlan_mac] = self.port_map['port_2']
                    mac_ips.append((mac_ipv4, macvlan_mac))
                return (mac_intfs, mac_ips, learned_mac_ports)

            def down_macvlans(macvlans):
                for macvlan in macvlans:
                    second_host.cmd(f'ip link set dev {macvlan} down')

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
        before_expiry_learned_macs = learned_macs

        # make sure they all eventually expire
        for _ in range(self.TIMEOUT * 3):
            learned_macs = self.hosts_learned(all_learned_mac_ports)
            self.verify_learn_counters(
                100, list(range(1, len(self.hosts_name_ordered()) + 1)))
            if not learned_macs:
                break
            time.sleep(1)

        self.assertFalse(learned_macs, msg=f'MACs did not expire: {learned_macs}')

        self.assertTrue(before_expiry_learned_macs)
        for mac in before_expiry_learned_macs:
            self.wait_until_no_matching_flow({'eth_dst': mac}, table_id=self._ETH_DST_TABLE)


class FaucetSingleHostsNoIdleTimeoutPrometheusTest(FaucetSingleHostsTimeoutPrometheusTest):

    """Test broken reset idle timer on flow refresh workaround."""

    CONFIG = """
        timeout: 15
        arp_neighbor_timeout: 4
        nd_neighbor_timeout: 4
        ignore_learn_ins: 0
        learn_jitter: 0
        cache_update_guard_time: 1
        idle_dst: False
""" + CONFIG_BOILER_UNTAGGED


class FaucetSingleL3LearnMACsOnPortTest(FaucetUntaggedTest):

    # TODO: currently set to accommodate least hardware
    def _max_hosts():  # pylint: disable=no-method-argument,no-self-use
        return 512

    MAX_HOSTS = _max_hosts()
    TEST_IPV4_NET = '10.0.0.0'
    TEST_IPV4_PREFIX = 16  # must hold more than MAX_HOSTS + 4
    LEARN_IPV4 = '10.0.254.254'
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        max_hosts: %u
        faucet_vips: ["10.0.254.254/16"]
""" % (_max_hosts() + 4)

    CONFIG = ("""
        ignore_learn_ins: 0
        metrics_rate_limit_sec: 3
        table_sizes:
            eth_src: %u
            eth_dst: %u
            ipv4_fib: %u
""" % (_max_hosts() + 64, _max_hosts() + 64, _max_hosts() + 64) + """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_2)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_3)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_4)d:
                native_vlan: 100
                max_hosts: 4096
""")

    def test_untagged(self):
        test_net = ipaddress.IPv4Network(
            f'{self.TEST_IPV4_NET}/{self.TEST_IPV4_PREFIX}')
        learn_ip = ipaddress.IPv4Address(self.LEARN_IPV4)
        self.verify_learning(test_net, learn_ip, 64, self.MAX_HOSTS)


class FaucetSingleL2LearnMACsOnPortTest(FaucetUntaggedTest):

    # TODO: currently set to accommodate least hardware
    def _max_hosts():  # pylint: disable=no-method-argument,no-self-use
        return 1024

    MAX_HOSTS = _max_hosts()
    TEST_IPV4_NET = '10.0.0.0'
    TEST_IPV4_PREFIX = 16  # must hold more than MAX_HOSTS + 4
    LEARN_IPV4 = '10.0.0.1'
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        max_hosts: %u
""" % (_max_hosts() + 4)

    CONFIG = ("""
        ignore_learn_ins: 0
        metrics_rate_limit_sec: 3
        table_sizes:
            eth_src: %u
            eth_dst: %u
""" % (_max_hosts() + 64, _max_hosts() + 64) + """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_2)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_3)d:
                native_vlan: 100
                max_hosts: 4096
            %(port_4)d:
                native_vlan: 100
                max_hosts: 4096
""")

    def test_untagged(self):
        test_net = ipaddress.IPv4Network(
            f'{self.TEST_IPV4_NET}/{self.TEST_IPV4_PREFIX}')
        learn_ip = ipaddress.IPv4Address(self.LEARN_IPV4)
        self.verify_learning(test_net, learn_ip, 64, self.MAX_HOSTS)


class FaucetUntaggedHUPTest(FaucetUntaggedTest):
    """Test handling HUP signal without config change."""

    def _configure_count_with_retry(self, expected_count):
        expected = [expected_count for _ in range(self.NUM_FAUCET_CONTROLLERS)]
        counts = []
        for _ in range(3):
            counts = []
            for controller in self.faucet_controllers:
                count = self.get_configure_count(controller=controller.name)
                counts.append(count)
            if counts == expected:
                break
            time.sleep(1)
        self.assertEqual(
            counts, expected,
            f'Controller configure counts {counts} != expected counts {expected}')

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
        for i in range(init_config_count, init_config_count + 3):
            self._configure_count_with_retry(i)
            with open(self.faucet_config_path, 'a', encoding='utf-8') as config_file:
                config_file.write('\n')
            self.verify_faucet_reconf(change_expected=False)
            self._configure_count_with_retry(i + 1)
            self.assertEqual(
                self.scrape_prometheus_var(
                    'of_dp_disconnections_total', dpid=True, default=None),
                0)
            self.assertEqual(
                self.scrape_prometheus_var(
                    'of_dp_connections_total', dpid=True, default=None),
                1)
            self.wait_until_controller_flow()
            self.ping_all_when_learned()
        for var in reload_type_vars:
            self.assertEqual(
                reload_vals[var],
                self.scrape_prometheus_var(var, dpid=True, default=None))


class FaucetIPv4TupleTest(FaucetTest):

    MAX_RULES = 1024
    ETH_TYPE = IPV4_ETH
    NET_BASE = ipaddress.IPv4Network('10.0.0.0/16')
    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""
    CONFIG = """
        table_sizes:
            port_acl: 1100
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
"""
    START_ACL_CONFIG = """
acls:
  1:
    exact_match: True
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

    def setUp(self):
        super().setUp()
        self.acl_config_file = os.path.join(self.tmpdir, 'acl.txt')
        self.CONFIG = '\n'.join(
            (self.CONFIG, f'include:\n     - {self.acl_config_file}'))
        with open(self.acl_config_file, 'w', encoding='utf-8') as acf:
            acf.write(self.START_ACL_CONFIG)
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
                    f'ipv{host_ip.version}_src': ip_match,
                    f'ipv{host_ip.version}_dst': ip_match,
                    'actions': {'allow': 1},
                }
                rules_yaml.append({'rule': rule_yaml})
            yaml_acl_conf = {'acls': {1: {'exact_match': True, 'rules': rules_yaml}}}
            tuple_txt = f'{len(rules_yaml)} IPv{host_ip.version} tuples\n'
            error(f'pushing {tuple_txt}')
            self.reload_conf(
                yaml_acl_conf, self.acl_config_file,  # pytype: disable=attribute-error
                restart=True, cold_start=False)
            error(f'pushed {tuple_txt}')
            self.wait_until_matching_flow(
                {'tp_src': port, 'ip_proto': 6, 'dl_type': eth_type}, table_id=0)
            rules *= 2

    def test_tuples(self):
        host_ips = list(itertools.islice(self.NET_BASE.hosts(), self.MAX_RULES))
        self._push_tuples(self.ETH_TYPE, host_ips)


class FaucetIPv6TupleTest(FaucetIPv4TupleTest):

    MAX_RULES = 1024
    ETH_TYPE = IPV6_ETH
    NET_BASE = ipaddress.IPv6Network('fc00::00/64')
    START_ACL_CONFIG = """
acls:
  1:
    exact_match: True
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
                acl_in: allow
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
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

    def setUp(self):
        super().setUp()
        self.ACL_COOKIE = random.randint(1, 2**16 - 1)
        self.ACL = self.ACL.replace('COOKIE', str(self.ACL_COOKIE))
        self.acl_config_file = f'{self.tmpdir}/acl.yaml'
        with open(self.acl_config_file, 'w', encoding='utf-8') as config_file:
            config_file.write(self.ACL)
        self.CONFIG = '\n'.join(
            (self.CONFIG, f'include:\n     - {self.acl_config_file}'))
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()


class FaucetDelPortTest(FaucetConfigReloadTestBase):

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
                acl_in: allow
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 200
"""

    def test_port_down_flow_gone(self):
        last_host = self.hosts_name_ordered()[-1]
        self.require_host_learned(last_host)
        second_host_dst_match = {'eth_dst': last_host.MAC()}
        self.wait_until_matching_flow(
            second_host_dst_match, table_id=self._ETH_DST_TABLE)
        self.change_port_config(
            self.port_map['port_4'], None, None,
            restart=True, cold_start=None)
        self.wait_until_no_matching_flow(
            second_host_dst_match, table_id=self._ETH_DST_TABLE)


class FaucetConfigReloadTest(FaucetConfigReloadTestBase):

    def test_add_unknown_dp(self):
        conf = self._get_faucet_conf()
        conf['dps']['unknown'] = {
            'dp_id': int(self.rand_dpid()),
            'hardware': 'Open vSwitch',
        }
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=False)

    def test_tabs_are_bad(self):
        self._enable_event_log()

        self.ping_all_when_learned()
        self.assertEqual(0, self.scrape_prometheus_var('faucet_config_load_error', dpid=False))
        event = self._wait_until_matching_event(lambda event: event['CONFIG_CHANGE']['success'])
        good_config_hash_info = event['CONFIG_CHANGE']['config_hash_info']
        self.assertNotEqual('', good_config_hash_info['hashes'])

        orig_conf = self._get_faucet_conf()
        self.force_faucet_reload(
            '\t'.join(('tabs', 'are', 'bad')))
        self.assertEqual(1, self.scrape_prometheus_var('faucet_config_load_error', dpid=False))
        event = self._wait_until_matching_event(lambda event: not event['CONFIG_CHANGE']['success'])
        self.assertEqual('', event['CONFIG_CHANGE']['config_hash_info']['hashes'])

        self.ping_all_when_learned()
        self.reload_conf(
            orig_conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=False)
        self.assertEqual(0, self.scrape_prometheus_var('faucet_config_load_error', dpid=False))
        event = self._wait_until_matching_event(lambda event: event['CONFIG_CHANGE']['success'])
        self.assertEqual(good_config_hash_info, event['CONFIG_CHANGE']['config_hash_info'])

    def test_port_change_vlan(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        third_host, fourth_host = self.hosts_name_ordered()[2:]
        self.ping_all_when_learned()
        self.change_port_config(
            self.port_map['port_1'], 'native_vlan', 200,
            restart=False, cold_start=False)
        self.wait_until_matching_flow(
            {'vlan_vid': 200}, table_id=self._ETH_SRC_TABLE,
            actions=['OUTPUT:CONTROLLER', f'GOTO_TABLE:{self._ETH_DST_TABLE}'])
        self.change_port_config(
            self.port_map['port_2'], 'native_vlan', 200,
            restart=True, cold_start=False)
        for port_name in ('port_1', 'port_2'):
            self.wait_until_matching_flow(
                {'in_port': int(self.port_map[port_name])},
                table_id=self._VLAN_TABLE,
                actions=['SET_FIELD: {vlan_vid:4296}'])
        self.one_ipv4_ping(first_host, second_host.IP(), require_host_learned=False)
        # hosts 1 and 2 now in VLAN 200, so they shouldn't see floods for 3 and 4.
        self.verify_vlan_flood_limited(
            third_host, fourth_host, first_host)

    def test_port_change_acl(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        orig_conf = self._get_faucet_conf()
        self.change_port_config(
            self.port_map['port_1'], 'acl_in', 1,
            cold_start=False)
        self.wait_until_matching_flow(
            {'in_port': int(self.port_map['port_1']),
             'eth_type': IPV4_ETH, 'tcp_dst': 5001, 'ip_proto': 6},
            table_id=self._PORT_ACL_TABLE, cookie=self.ACL_COOKIE)
        self.wait_until_matching_flow(
            {'vlan_vid': 100}, table_id=self._ETH_SRC_TABLE,
            actions=['OUTPUT:CONTROLLER', f'GOTO_TABLE:{self._ETH_DST_TABLE}'])
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
        first_host, second_host, third_host = self.hosts_name_ordered()[0:3]
        self.change_port_config(
            self.port_map['port_1'], 'permanent_learn', True,
            restart=True, cold_start=False)
        self.ping_all_when_learned(hard_timeout=0)
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.ping((second_host, third_host)))
        self.retry_net_ping(hosts=(first_host, second_host))
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned(hard_timeout=0)
        self.change_port_config(
            self.port_map['port_1'], 'acl_in', 1,
            restart=True, cold_start=False)
        self.wait_until_matching_flow(
            {'in_port': int(self.port_map['port_1']),
             'eth_type': IPV4_ETH, 'tcp_dst': 5001, 'ip_proto': 6},
            table_id=self._PORT_ACL_TABLE)
        self.verify_tp_dst_blocked(5001, first_host, second_host)
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetDeleteConfigReloadTest(FaucetConfigReloadTestBase):

    def test_delete_interface(self):
        # With all ports changed, we should cold start.
        conf = self._get_faucet_conf()
        del conf['dps'][self.DP_NAME]['interfaces']
        conf['dps'][self.DP_NAME]['interfaces'] = {
            int(self.port_map['port_1']): {
                'native_vlan': 100,
                'tagged_vlans': [200],
            }
        }
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=True, change_expected=True)


class FaucetRouterConfigReloadTest(FaucetConfigReloadTestBase):

    def test_router_config_reload(self):
        conf = self._get_faucet_conf()
        conf['routers'] = {
            'router-1': {
                'vlans': [100, 200],
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
                acls_in: [allow]
            %(port_2)d:
                native_vlan: 100
                acl_in: allow
            %(port_3)d:
                native_vlan: 100
                acl_in: deny
            %(port_4)d:
                native_vlan: 100
                acl_in: deny
"""

    def _verify_hosts_learned(self, hosts):
        self.ping_all()
        for host in hosts:
            self.require_host_learned(host)
        self.assertEqual(len(hosts), self.scrape_prometheus_var(
            'vlan_hosts_learned', {'vlan': '100'}))

    def test_port_acls(self):
        hup = not self.STAT_RELOAD
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]
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


class FaucetConfigReloadMACFlushTest(FaucetConfigReloadTestBase):

    def test_port_change_vlan(self):
        self.ping_all_when_learned()
        self.assertEqual(4, len(self.scrape_prometheus(var='learned_l2_port')))
        self.change_port_config(
            self.port_map['port_1'], 'native_vlan', 200,
            restart=False, cold_start=False)
        self.wait_until_matching_flow(
            {'vlan_vid': 200}, table_id=self._ETH_SRC_TABLE,
            actions=['OUTPUT:CONTROLLER', f'GOTO_TABLE:{self._ETH_DST_TABLE}'])
        self.change_port_config(
            self.port_map['port_2'], 'native_vlan', 200,
            restart=True, cold_start=False)
        for port_name in ('port_1', 'port_2'):
            self.wait_until_matching_flow(
                {'in_port': int(self.port_map[port_name])},
                table_id=self._VLAN_TABLE,
                actions=['SET_FIELD: {vlan_vid:4296}'])
        self.assertEqual(0, len(self.scrape_prometheus(var='learned_l2_port')))


class FaucetConfigReloadEmptyAclTest(FaucetConfigReloadTestBase):

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 300
            %(port_4)d:
                native_vlan: 100
"""
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
    200:
        description: "untagged"
    300:
        description: "untagged"
        acls_in: [1]
"""

    STAT_RELOAD = '1'

    def test_port_acls(self):
        hup = not self.STAT_RELOAD
        self.change_port_config(
            self.port_map['port_3'], 'acls_in', [],
            restart=True, cold_start=False, hup=hup, change_expected=False)
        self.change_port_config(
            self.port_map['port_1'], 'acls_in', [],
            restart=True, cold_start=False, hup=hup, change_expected=False)


class FaucetConfigStatReloadAclTest(FaucetConfigReloadAclTest):

    # Use the stat-based reload method.
    STAT_RELOAD = '1'


class FaucetUntaggedBGPDualstackDefaultRouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import default route from BGP."""

    NUM_FAUCET_CONTROLLERS = 1

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24", "fc00::1:254/112"]
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["127.0.0.1", "::1"]
            neighbor_addresses: ["127.0.0.1", "::1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_peer_conf = """
    static {
      route 0.0.0.0/0 next-hop 10.0.0.1 local-preference 100;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        self.assertEqual(self.NUM_FAUCET_CONTROLLERS, 1)
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host_alias_ip = ipaddress.ip_interface('10.99.99.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}, default=0),
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

    NUM_FAUCET_CONTROLLERS = 1

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["127.0.0.1"]
            neighbor_addresses: ["127.0.0.1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_peer_conf = """
    static {
      route 0.0.0.0/0 next-hop 10.0.0.1 local-preference 100;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        self.assertEqual(self.NUM_FAUCET_CONTROLLERS, 1)
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host_alias_ip = ipaddress.ip_interface('10.99.99.99/24')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.host_ipv4_alias(first_host, first_host_alias_ip)
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}, default=0),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.add_host_route(
            second_host, first_host_alias_host_ip, self.FAUCET_VIPV4.ip)
        self.one_ipv4_ping(second_host, first_host_alias_ip.ip)
        self.one_ipv4_controller_ping(first_host)
        self.coldstart_conf()


class FaucetUntaggedBGPIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and import from BGP."""

    NUM_FAUCET_CONTROLLERS = 1
    NUM_GAUGE_CONTROLLERS = 1

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["127.0.0.1"]
            neighbor_addresses: ["127.0.0.1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

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

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        """Test IPv4 routing, and BGP routes received."""
        self.assertEqual(self.NUM_FAUCET_CONTROLLERS, 1)
        first_host, second_host = self.hosts_name_ordered()[:2]
        # wait until 10.0.0.1 has been resolved
        self.wait_for_route_as_flow(
            first_host.MAC(), ipaddress.IPv4Network('10.99.99.0/24'))
        self.wait_bgp_up(
            mininet_test_util.LOCALHOST, 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '4', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route(r'.+10.0.4.0\/24.+cannot be us$')
        self.verify_invalid_bgp_route(r'.+10.0.5.0\/24.+because nexthop not in VLAN.+')
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv4Network('10.0.3.0/24'))
        self.verify_ipv4_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv4_routing_mesh()
        for host in first_host, second_host:
            self.one_ipv4_controller_ping(host)
        self.verify_traveling_dhcp_mac()


class FaucetUntaggedIPv4RouteTest(FaucetUntaggedTest):
    """Test IPv4 routing and export to BGP."""

    NUM_FAUCET_CONTROLLERS = 1

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
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["127.0.0.1"]
            neighbor_addresses: ["127.0.0.1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
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
        for route_string in (
                '10.0.0.0/24 next-hop 10.0.0.254',
                '10.0.1.0/24 next-hop 10.0.0.1',
                '10.0.2.0/24 next-hop 10.0.0.2',
                '10.0.3.0/24 next-hop 10.0.0.2'):
            self.assertTrue(re.search(route_string, updates), msg=updates)
        # test nexthop expired when port goes down
        first_host = self.hosts_name_ordered()[0]
        match, table = self.match_table(ipaddress.IPv4Network('10.0.0.1/32'))
        ofmsg = None
        for _ in range(5):
            self.one_ipv4_controller_ping(first_host)
            ofmsg = self.get_matching_flow(match, table_id=table)
            if ofmsg:
                break
            time.sleep(1)
        self.assertTrue(ofmsg, msg=match)
        self.set_port_down(self.port_map['port_1'])
        for _ in range(5):
            if not self.get_matching_flow(match, table_id=table):
                return
            time.sleep(1)
        self.fail(f'host route {match} still present')


class FaucetUntaggedRestBcastIPv4RouteTest(FaucetUntaggedIPv4RouteTest):

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        interfaces:
            %(port_1)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_2)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_3)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_4)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
"""


class FaucetUntaggedVLanUnicastFloodTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        unicast_flood: True
"""

    CONFIG = CONFIG_BOILER_UNTAGGED

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

    CONFIG = CONFIG_BOILER_UNTAGGED

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
                unicast_flood: True
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
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
                unicast_flood: False
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        self.assertFalse(self.bogus_mac_flooded_to_port1())


class FaucetUntaggedHostMoveTest(FaucetUntaggedTest):

    def test_untagged(self):
        self._enable_event_log()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        for _ in range(2):
            self.retry_net_ping(hosts=(first_host, second_host))
            self.ping((first_host, second_host))
            for host, in_port in (
                    (first_host, self.port_map['port_1']),
                    (second_host, self.port_map['port_2'])):
                self.require_host_learned(host, in_port=in_port)
            self.swap_host_macs(first_host, second_host)
        for port in (self.port_map['port_1'], self.port_map['port_2']):
            self.wait_until_matching_lines_from_file(
                r'.+L2_LEARN.+"previous_port_no": %u.+' % port, self.event_log)


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
                permanent_learn: True
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        self.ping_all_when_learned(hard_timeout=0)
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]
        self.assertTrue(self.prom_mac_learned(first_host.MAC(), port=self.port_map['port_1']))

        # 3rd host impersonates 1st but 1st host still OK
        original_third_host_mac = third_host.MAC()
        third_host.setMAC(first_host.MAC())
        self.assertEqual(100.0, self.ping((second_host, third_host)))
        self.assertTrue(self.prom_mac_learned(first_host.MAC(), port=self.port_map['port_1']))
        self.assertFalse(self.prom_mac_learned(first_host.MAC(), port=self.port_map['port_3']))
        self.retry_net_ping(hosts=(first_host, second_host))

        # 3rd host stops impersonating, now everything fine again.
        third_host.setMAC(original_third_host_mac)
        self.ping_all_when_learned(hard_timeout=0)


class FaucetCoprocessorTest(FaucetUntaggedTest):

    N_UNTAGGED = 3
    N_TAGGED = 1

    CONFIG = """
        interfaces:
            %(port_1)d:
                coprocessor: {strategy: vlan_vid}
                mirror: %(port_4)d
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        # Inject packet into pipeline using coprocessor.
        coprocessor_host, first_host, second_host, _ = self.hosts_name_ordered()
        self.one_ipv4_ping(first_host, second_host.IP())
        tcpdump_filter = ' and '.join((
            f'ether dst {first_host.MAC()}',
            f'ether src {coprocessor_host.MAC()}',
            'icmp'))
        cmds = [
            lambda: coprocessor_host.cmd(
                'arp -s %s %s' % (first_host.IP(), first_host.MAC())),
            lambda: coprocessor_host.cmd(
                'fping %s -c3 %s' % (self.FPING_ARGS_SHORT, first_host.IP())),
        ]
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, cmds, timeout=5, vflags='-vv', packets=1)
        self.assertFalse(self.tcpdump_rx_packets(tcpdump_txt, packets=0))


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
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
                loop_protect: True
            %(port_4)d:
                native_vlan: 100
                loop_protect: True
"""

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def total_port_bans(self):
        total_bans = 0
        for i in range(self.LINKS_PER_HOST * self.N_UNTAGGED):
            port_labels = self.port_labels(self.port_map[f'port_{i + 1}'])
            total_bans += self.scrape_prometheus_var(
                'port_learn_bans', port_labels, dpid=True, default=0)
        return total_bans

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()
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
            f'brctl addif br-loop1 {second_host.name}-eth0',
            # Connect other leg of veth pair.
            'brctl addbr br-loop2',
            'brctl setfd br-loop2 0',
            'ip link set br-loop2 up',
            'brctl addif br-loop2 veth-loop2',
            f'brctl addif br-loop2 {second_host.name}-eth1'))

        # Flood some traffic into the loop
        for _ in range(3):
            first_host.cmd('fping %s -c3 10.0.0.254' % self.FPING_ARGS_SHORT)
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
        lacp_timeout: 3
        interfaces:
            %(port_1)d:
                native_vlan: 100
                lacp: 1
                lacp_port_priority: 1
                lacp_port_id: 100
            %(port_2)d:
                native_vlan: 100
                lacp: 1
                lacp_port_priority: 2
                lacp_port_id: 101
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST, hw_dpid=self.hw_dpid)
        self.start_net()

    def test_untagged(self):
        first_host = self.hosts_name_ordered()[0]

        def get_lacp_port_id(port):
            port_labels = self.port_labels(port)
            lacp_port_id = self.scrape_prometheus_var('lacp_port_id', port_labels, default=0)
            return lacp_port_id

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
        lag_ports = (1, 2)
        synced_state_txt = r"""
Slave Interface: \S+-eth0
MII Status: up
Speed: \d+ Mbps
Duplex: full
Link Failure Count: \d+
Permanent HW addr: \S+
Slave queue ID: 0
Aggregator ID: \d+
Actor Churn State: monitoring
Partner Churn State: monitoring
Actor Churned Count: \d+
Partner Churned Count: \d+
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
    port priority: 1
    port number: %d
    port state: 62

Slave Interface: \S+-eth1
MII Status: up
Speed: \d+ Mbps
Duplex: full
Link Failure Count: \d+
Permanent HW addr: \S+
Slave queue ID: 0
Aggregator ID: \d+
Actor Churn State: monitoring
Partner Churn State: monitoring
Actor Churned Count: \d+
Partner Churned Count: \d+
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
    port priority: 2
    port number: %d
    port state: 62
""".strip() % tuple(get_lacp_port_id(self.port_map[f'port_{i}']) for i in lag_ports)

        lacp_timeout = 5

        def prom_lacp_up_ports():
            lacp_up_ports = 0
            for lacp_port in lag_ports:
                port_labels = self.port_labels(self.port_map[f'port_{lacp_port}'])
                lacp_state = self.scrape_prometheus_var('port_lacp_state', port_labels, default=0)
                lacp_up_ports += 1 if lacp_state == 3 else 0
            return lacp_up_ports

        def require_lag_up_ports(expected_up_ports):
            for _ in range(lacp_timeout * 10):
                if prom_lacp_up_ports() == expected_up_ports:
                    break
                time.sleep(1)
            self.assertEqual(prom_lacp_up_ports(), expected_up_ports)

        def require_linux_bond_up():
            for _retries in range(lacp_timeout * 2):
                result = first_host.cmd('cat /proc/net/bonding/%s|sed "s/[ \t]*$//g"' % bond)
                result = '\n'.join([line.rstrip() for line in result.splitlines()])
                with open(os.path.join(self.tmpdir, 'bonding-state.txt'), 'w', encoding='utf-8') as state_file:
                    state_file.write(result)
                if re.search(synced_state_txt, result):
                    break
                time.sleep(1)
            self.assertTrue(
                re.search(synced_state_txt, result),
                msg=f'LACP did not synchronize: {result}\n\nexpected:\n\n{synced_state_txt}')

        # Start with ports down.
        for port in lag_ports:
            self.set_port_down(self.port_map[f'port_{port}'])
        require_lag_up_ports(0)
        orig_ip = first_host.IP()
        switch = self.first_switch()
        bond_members = [pair[0].name for pair in first_host.connectionsTo(switch)]
        # Deconfigure bond members
        for bond_member in bond_members:
            self.quiet_commands(first_host, (
                f'ip link set {bond_member} down',
                f'ip address flush dev {bond_member}'))
        # Configure bond interface
        self.quiet_commands(first_host, (
            f'ip link add {bond} address 0e:00:00:00:00:99 type bond mode 802.3ad lacp_rate fast miimon 100',
            f'ip add add {orig_ip}/24 dev {bond}',
            f'ip link set {bond} up'))
        # Add bond members
        for bond_member in bond_members:
            self.quiet_commands(first_host, (
                f'ip link set dev {bond_member} master {bond}',))

        for _flaps in range(2):
            # All ports down.
            for port in lag_ports:
                self.set_port_down(self.port_map[f'port_{port}'])
            require_lag_up_ports(0)
            # Pick a random port to come up.
            up_port = random.choice(lag_ports)
            self.set_port_up(self.port_map[f'port_{up_port}'])
            require_lag_up_ports(1)
            # We have connectivity with only one port.
            self.one_ipv4_ping(
                first_host, self.FAUCET_VIPV4.ip, require_host_learned=False, intf=bond, retries=5)
            for port in lag_ports:
                self.set_port_up(self.port_map[f'port_{port}'])
            # We have connectivity with two ports.
            require_lag_up_ports(2)
            require_linux_bond_up()
            self.one_ipv4_ping(
                first_host, self.FAUCET_VIPV4.ip, require_host_learned=False, intf=bond, retries=5)
            # We have connectivity if that random port goes down.
            self.set_port_down(self.port_map[f'port_{up_port}'])
            require_lag_up_ports(1)
            self.one_ipv4_ping(
                first_host, self.FAUCET_VIPV4.ip, require_host_learned=False, intf=bond, retries=5)
            for port in lag_ports:
                self.set_port_up(self.port_map[f'port_{port}'])


class FaucetUntaggedIPv4LACPMismatchTest(FaucetUntaggedIPv4LACPTest):
    """Ensure remote LACP system ID mismatch is logged."""

    def test_untagged(self):
        first_host = self.hosts_name_ordered()[0]
        orig_ip = first_host.IP()
        switch = self.first_switch()
        bond_members = [pair[0].name for pair in first_host.connectionsTo(switch)]
        for i, bond_member in enumerate(bond_members):
            bond = f'bond{i}'
            self.quiet_commands(first_host, (
                f'ip link set {bond_member} down',
                f'ip address flush dev {bond_member}',
                ('ip link add %s address 0e:00:00:00:00:%2.2x '
                 'type bond mode 802.3ad lacp_rate fast miimon 100') % (bond, i * 2 + i),
                f'ip add add {orig_ip}/24 dev {bond}',
                f'ip link set {bond} up',
                f'ip link set dev {bond_member} master {bond}'))
        self.wait_until_matching_lines_from_faucet_log_files(r'.+actor system mismatch.+')


class FaucetUntaggedIPv4ControlPlaneFuzzTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_ping_fragment_controller(self):
        first_host = self.hosts_name_ordered()[0]
        first_host.cmd('ping -s 1476 -c 3 %s' % self.FAUCET_VIPV4.ip)
        self.one_ipv4_controller_ping(first_host)

    def test_fuzz_controller(self):
        first_host = self.hosts_name_ordered()[0]
        self.one_ipv4_controller_ping(first_host)
        packets = 1000
        fuzz_template = 'python3 -c \"from scapy.all import * ; scapy.all.send(%s, count=%u)\"'
        for fuzz_cmd in (
                fuzz_template % ('IP(dst=\'%s\')/fuzz(%s(type=0))' % (self.FAUCET_VIPV4.ip, 'ICMP'), packets),
                fuzz_template % ('IP(dst=\'%s\')/fuzz(%s(type=8))' % (self.FAUCET_VIPV4.ip, 'ICMP'), packets),
                fuzz_template % ('fuzz(%s(pdst=\'%s\'))' % ('ARP', self.FAUCET_VIPV4.ip), packets)):
            fuzz_out = first_host.cmd(mininet_test_util.timeout_cmd(fuzz_cmd, 180))
            self.assertTrue(
                re.search(f'Sent {packets} packets', fuzz_out), msg=f'{fuzz_cmd}: {fuzz_out}')
        self.one_ipv4_controller_ping(first_host)

    def test_flap_ping_controller(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        for _ in range(5):
            self.one_ipv4_ping(first_host, second_host.IP())
            for host in first_host, second_host:
                self.one_ipv4_controller_ping(host)
            self.flap_all_switch_ports()


class FaucetUntaggedIPv4ControlPlaneTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_fping_controller(self):
        first_host = self.hosts_name_ordered()[0]
        self.one_ipv4_controller_ping(first_host)
        # Try 64 byte icmp packets
        self.verify_controller_fping(first_host, self.FAUCET_VIPV4)
        # Try 128 byte icmp packets
        self.verify_controller_fping(first_host, self.FAUCET_VIPV4, size=128)


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
""" + CONFIG_BOILER_UNTAGGED

    def test_ndisc6(self):
        first_host = self.hosts_name_ordered()[0]
        for vip in ('fe80::1:254', 'fc00::1:254', 'fc00::2:254'):
            self.assertEqual(
                self.FAUCET_MAC.upper(),
                first_host.cmd(f'ndisc6 -q {vip} {first_host.defaultIntf()}').strip())

    def test_rdisc6(self):
        first_host = self.hosts_name_ordered()[0]
        rdisc6_results = sorted(list(set(first_host.cmd(
            f'rdisc6 -q {first_host.defaultIntf()}').splitlines())))
        self.assertEqual(
            ['fc00::1:0/112', 'fc00::2:0/112'],
            rdisc6_results)

    def test_ra_advertise(self):
        first_host = self.hosts_name_ordered()[0]
        tcpdump_filter = ' and '.join((
            'ether dst 33:33:00:00:00:01',
            f'ether src {self.FAUCET_MAC}',
            'icmp6',
            'ip6[40] == 134',
            'ip6 host fe80::1:254'))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [], timeout=30, vflags='-vv', packets=1)
        for ra_required in (
                r'ethertype IPv6 \(0x86dd\), length 142',
                r'fe80::1:254 > ff02::1:.+ICMP6, router advertisement',
                r'fc00::1:0/112, Flags \[onlink, auto\]',
                r'fc00::2:0/112, Flags \[onlink, auto\]',
                r'source link-address option \(1\), length 8 \(1\): %s' % self.FAUCET_MAC):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg=f'{ra_required}: {tcpdump_txt}')

    def test_rs_reply(self):
        first_host = self.hosts_name_ordered()[0]
        tcpdump_filter = ' and '.join((
            f'ether src {self.FAUCET_MAC}',
            f'ether dst {first_host.MAC()}',
            'icmp6',
            'ip6[40] == 134',
            'ip6 host fe80::1:254'))
        tcpdump_txt = self.tcpdump_helper(
            first_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'rdisc6 -1 {first_host.defaultIntf()}')],
            timeout=30, vflags='-vv', packets=1)
        for ra_required in (
                r'fe80::1:254 > fe80::.+ICMP6, router advertisement',
                r'fc00::1:0/112, Flags \[onlink, auto\]',
                r'fc00::2:0/112, Flags \[onlink, auto\]',
                r'source link-address option \(1\), length 8 \(1\): %s' % self.FAUCET_MAC):
            self.assertTrue(
                re.search(ra_required, tcpdump_txt),
                msg=f'{ra_required}: {tcpdump_txt} ({tcpdump_filter})')


class FaucetUntaggedIPv6ControlPlaneFuzzTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_flap_ping_controller(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        for _ in range(5):
            self.one_ipv6_ping(first_host, 'fc00::1:2')
            for host in first_host, second_host:
                self.one_ipv6_controller_ping(host)
            self.flap_all_switch_ports()

    def test_fuzz_controller(self):
        first_host = self.hosts_name_ordered()[0]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.one_ipv6_controller_ping(first_host)
        fuzz_success = False
        packets = 1000
        count = 0
        abort = False

        def note(*args):
            error(f'{self._test_name()}:', *args + tuple('\n'))

        # Some of these tests have been slowing down and timing out,
        # So this code is intended to allow some debugging and analysis
        for fuzz_class in dir(scapy.all):
            if fuzz_class.startswith('ICMPv6'):
                fuzz_cmd = ("from scapy.all import * ;"
                            "scapy.all.send(IPv6(dst='%s')/fuzz(%s()),count=%u)" %
                            (self.FAUCET_VIPV6.ip, fuzz_class, packets))
                out, start, too_long = '', time.time(), 30  # seconds
                popen = first_host.popen('python3', '-c', fuzz_cmd)
                for _, line in pmonitor({first_host: popen}):
                    out += line
                    if time.time() - start > too_long:
                        note('stopping', fuzz_class, 'after >', too_long, 'seconds')
                        note('output was:', out)
                        popen.terminate()
                        abort = True
                        break
                popen.wait()
                if f'Sent {packets} packets' in out:
                    count += packets
                    elapsed = time.time() - start
                    note('sent', packets, fuzz_class, 'packets in %.2fs' % elapsed)
                    fuzz_success = True
                if abort:
                    break
        note('successfully sent', count, 'packets')
        self.assertTrue(fuzz_success)
        note('pinging', first_host)
        self.one_ipv6_controller_ping(first_host)
        note('test_fuzz_controller() complete')


class FaucetUntaggedIPv6ControlPlaneTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_fping_controller(self):
        first_host = self.hosts_name_ordered()[0]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.one_ipv6_controller_ping(first_host)
        # Try 64 byte icmp6 packets
        self.verify_controller_fping(first_host, self.FAUCET_VIPV6)
        # Try 128 byte icmp6 packets
        self.verify_controller_fping(first_host, self.FAUCET_VIPV6, size=128)


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
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                native_vlan: 101
            %(port_4)d:
                native_vlan: 101
"""

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=2, n_untagged=2, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_separate_untagged_tagged(self):
        tagged_host_pair = self.hosts_name_ordered()[:2]
        untagged_host_pair = self.hosts_name_ordered()[2:]
        self.verify_vlan_flood_limited(
            tagged_host_pair[0], tagged_host_pair[1], untagged_host_pair[0])
        self.verify_vlan_flood_limited(
            untagged_host_pair[0], untagged_host_pair[1], tagged_host_pair[0])
        # hosts within VLANs can ping each other
        self.retry_net_ping(hosts=tagged_host_pair)
        self.retry_net_ping(hosts=untagged_host_pair)
        # hosts cannot ping hosts in other VLANs
        self.assertEqual(
            100, self.ping([tagged_host_pair[0], untagged_host_pair[0]]))


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
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_notblocked(5002, first_host, second_host)


class FaucetUntaggedEgressACLTest(FaucetUntaggedTest):

    REQUIRES_METADATA = True
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        acl_out: 1
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
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_port5001_blocked(self):
        egress_acl_table = self.scrape_prometheus_var(
            'faucet_config_table_names',
            labels={'table_name': 'egress_acl'}
        )
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(
            5001, first_host, second_host, table_id=egress_acl_table)
        self.ping_all_when_learned()
        self.verify_tp_dst_blocked(
            5001, first_host, second_host, table_id=egress_acl_table)

    def test_port5002_notblocked(self):
        egress_acl_table = self.scrape_prometheus_var(
            'faucet_config_table_names',
            labels={'table_name': 'egress_acl'}
        )
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=egress_acl_table)


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
""" + CONFIG_BOILER_UNTAGGED

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(5001, first_host, second_host)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
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
                acl_in: 1
                opstatus_reconf: False
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        matches = {
            'in_port': int(self.port_map['port_1']),
            'tcp_dst': 5001,
            'eth_type': IPV4_ETH,
            'ip_proto': 6}
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
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
        first_host, second_host = self.hosts_name_ordered()[0:2]
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
    CONFIG = CONFIG_BOILER_UNTAGGED

    def test_port5001_blocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_blocked(
            5001, first_host, second_host, table_id=self._VLAN_ACL_TABLE)

    def test_port5002_notblocked(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.verify_tp_dst_notblocked(
            5002, first_host, second_host, table_id=self._VLAN_ACL_TABLE)


class FaucetUntaggedOutputOnlyTest(FaucetUntaggedTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                output_only: True
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        self.wait_until_matching_flow(
            {'in_port': int(self.port_map['port_1'])},
            table_id=self._VLAN_TABLE,
            actions=[])
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]
        self.assertEqual(100.0, self.ping((first_host, second_host)))
        self.assertEqual(0, self.ping((third_host, second_host)))


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
                mirror: %(port_3)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 1
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
        self.verify_ping_mirrored(first_host, second_host, mirror_host)

    def test_eapol_mirrored(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
        self.verify_eapol_mirrored(first_host, second_host, mirror_host)


class FaucetUntaggedACLOutputMirrorTest(FaucetUntaggedTest):

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
                output:
                    ports: [%(port_3)d]
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 1
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
        self.verify_ping_mirrored(first_host, second_host, mirror_host)


class FaucetUntaggedOrderedACLOutputMirrorTest(FaucetUntaggedTest):

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
                output:
                    - ports: [%(port_3)d]
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 1
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
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
                mirror: %(port_3)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
                acl_in: 1
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
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
                    ports: [%(port_2)d, %(port_3)d]
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: multi_out
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 200
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, third_host, fourth_host = self.hosts_name_ordered()[0:4]
        tcpdump_filter = ('icmp')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            third_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {third_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, third_host.IP())))])
        self.assertTrue(re.search(
            f'{third_host.IP()}: ICMP echo request', tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            fourth_host, tcpdump_filter, [
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, fourth_host.IP())))])
        self.assertFalse(re.search(
            f'{fourth_host.IP()}: ICMP echo request', tcpdump_txt))


class FaucetMultiOrderedOutputTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
    200:
acls:
    multi_out:
        - rule:
            actions:
                output:
                    - ports: [%(port_2)d, %(port_3)d]
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: multi_out
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 200
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, third_host, fourth_host = self.hosts_name_ordered()[0:4]
        tcpdump_filter = ('icmp')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            third_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {third_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, third_host.IP())))])
        self.assertTrue(re.search(
            f'{third_host.IP()}: ICMP echo request', tcpdump_txt))
        tcpdump_txt = self.tcpdump_helper(
            fourth_host, tcpdump_filter, [
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, fourth_host.IP())))])
        self.assertFalse(re.search(
            f'{fourth_host.IP()}: ICMP echo request', tcpdump_txt))


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
                    port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = ('icmp and ether dst 06:06:06:06:06:06')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 123', tcpdump_txt))


class FaucetUntaggedOrderedOutputTest(FaucetUntaggedTest):

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
                    - vlan_vid: 123
                    - set_fields:
                        - eth_dst: "06:06:06:06:06:06"
                    - port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = ('icmp and ether dst 06:06:06:06:06:06')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
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
                    port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = 'vlan'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 456.+vlan 123', tcpdump_txt))


class FaucetUntaggedMultiVlansOrderedOutputTest(FaucetUntaggedTest):

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
                    - set_fields:
                        - eth_dst: "06:06:06:06:06:06"
                    - vlan_vids: [123, 456]
                    - port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = 'vlan'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))])
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 456.+vlan 123', tcpdump_txt))


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
                    port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = 'ether proto 0x88a8'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            packets=1)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt), msg=tcpdump_txt)
        self.assertTrue(re.search(
            'vlan 456.+ethertype 802.1Q-QinQ, vlan 123', tcpdump_txt), msg=tcpdump_txt)


class FaucetUntaggedMultiConfVlansOrderedOutputTest(FaucetUntaggedTest):

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
                    - set_fields:
                        - eth_dst: "06:06:06:06:06:06"
                    - vlan_vids: [{vid: 123, eth_type: 0x88a8}, 456]
                    - port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the rewritten address and VLAN
        tcpdump_filter = 'ether proto 0x88a8'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            packets=1)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt), msg=tcpdump_txt)
        self.assertTrue(re.search(
            'vlan 456.+ethertype 802.1Q-QinQ, vlan 123', tcpdump_txt), msg=tcpdump_txt)


class FaucetUntaggedMirrorTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                output_only: True
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
        first_host_ip = ipaddress.ip_address(first_host.IP())
        second_host_ip = ipaddress.ip_address(second_host.IP())
        self.flap_all_switch_ports()
        # Add mirror, test performance.
        self.change_port_config(
            self.port_map['port_3'], 'mirror', self.port_map['port_1'],
            restart=True, cold_start=False)
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        self.verify_bcast_ping_mirrored(first_host, second_host, mirror_host)
        self.verify_iperf_min(
            ((first_host, self.port_map['port_1']),
             (second_host, self.port_map['port_2'])),
            MIN_MBPS, first_host_ip, second_host_ip,
            sync_counters_func=lambda: self.one_ipv4_ping(first_host, second_host_ip))
        # Remove mirror, test performance.
        self.change_port_config(
            self.port_map['port_3'], 'mirror', [],
            restart=True, cold_start=False)
        self.verify_iperf_min(
            ((first_host, self.port_map['port_1']),
             (second_host, self.port_map['port_2'])),
            MIN_MBPS, first_host_ip, second_host_ip,
            sync_counters_func=lambda: self.one_ipv4_ping(first_host, second_host_ip))


class FaucetUntaggedMultiMirrorTest(FaucetUntaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                output_only: True
            %(port_4)d:
                output_only: True
"""

    def test_untagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[:3]
        ping_pairs = (
            (first_host, second_host),
            (second_host, first_host))
        self.flap_all_switch_ports()
        self.change_port_config(
            self.port_map['port_3'], 'mirror',
            [self.port_map['port_1'], self.port_map['port_2']],
            restart=True, cold_start=False, hup=True)
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
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                mirror: %(port_1)d
            %(port_4)d:
                mirror: %(port_1)d
"""

    def test_untagged(self):
        self.flap_all_switch_ports()

        # Make sure the two hosts both mirror from port 1
        first_host, second_host = self.hosts_name_ordered()[0:2]
        mirror_host = self.hosts_name_ordered()[2]
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        mirror_host = self.hosts_name_ordered()[3]
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

    CONFIG = CONFIG_TAGGED_BOILER

    def setUp(self):
        super().setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=4, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_tagged(self):
        # Untagged traffic specifically dropped.
        for host in self.hosts_name_ordered():
            host.cmd(self.scapy_dhcp(host.MAC(), host.intf_root_name, count=3))
        for port in self.port_map.values():
            self.wait_nonzero_packet_count_flow(
                {'in_port': port, 'vlan_tci': '0x0000/0x1fff'}, table_id=self._VLAN_TABLE)
        self.ping_all_when_learned()


class FaucetTaggedDTPTest(FaucetTaggedTest):

    def test_tagged(self):
        for host in self.hosts_name_ordered():
            scapy_txt = host.cmd(
                ('python3 -c \"import sys ; from scapy.contrib.dtp import * ;'
                 'negotiate_trunk(iface=\'%s\')\"' % host.intf_root_name))
            self.assertTrue(re.search('Sent 1 packets', scapy_txt), msg=scapy_txt)
        super().test_tagged()


class FaucetTaggedMirrorTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                # port 3 will mirror port 1
                mirror: %(port_1)d
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[0:3]
        self.flap_all_switch_ports()
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        self.verify_bcast_ping_mirrored(first_host, second_host, mirror_host)
        first_host_ip = ipaddress.ip_address(first_host.IP())
        second_host_ip = ipaddress.ip_address(second_host.IP())
        self.verify_iperf_min(
            ((first_host, self.port_map['port_1']),
             (second_host, self.port_map['port_2'])),
            MIN_MBPS, first_host_ip, second_host_ip,
            sync_counters_func=lambda: self.one_ipv4_ping(first_host, second_host_ip))
        tagged_ports = (self.port_map['port_1'], self.port_map['port_2'], self.port_map['port_4'])
        for port in tagged_ports:
            self.wait_until_matching_flow(
                {'vlan_vid': 100, 'in_port': port},
                table_id=self._VLAN_TABLE,
                actions=[f'GOTO_TABLE:{self._ETH_SRC_TABLE}'])
        self.change_port_config(
            self.port_map['port_3'], 'mirror', None,
            restart=True, cold_start=False)
        for port in tagged_ports:
            self.wait_until_matching_flow(
                {'vlan_vid': 100, 'in_port': port},
                table_id=self._VLAN_TABLE,
                actions=[f'GOTO_TABLE:{self._ETH_SRC_TABLE}'])


class FaucetTaggedVLANPCPTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
acls:
    1:
        - rule:
            vlan_vid: 100
            vlan_pcp: 1
            actions:
                output:
                    set_fields:
                        - vlan_pcp: 2
                allow: 1
        - rule:
            actions:
                allow: 1
"""
    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.quiet_commands(
            first_host,
            [f'ip link set {first_host.defaultIntf()} type vlan egress {i}:1'
                for i in range(0, 8)])
        self.one_ipv4_ping(first_host, second_host.IP())
        self.wait_nonzero_packet_count_flow(
            {'vlan_vid': 100, 'vlan_pcp': 1}, table_id=self._PORT_ACL_TABLE)
        tcpdump_filter = f'ether dst {second_host.MAC()}'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'ping -c3 {second_host.IP()}')], root_intf=True, packets=1)
        self.assertTrue(re.search('vlan 100, p 2,', tcpdump_txt))


class FaucetTaggedVLANPCPOrderedTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
acls:
    1:
        - rule:
            vlan_vid: 100
            vlan_pcp: 1
            actions:
                output:
                    - set_fields:
                        - vlan_pcp: 2
                allow: 1
        - rule:
            actions:
                allow: 1
"""
    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.quiet_commands(
            first_host,
            [f'ip link set {first_host.defaultIntf()} type vlan egress {i}:1'
                for i in range(0, 8)])
        self.one_ipv4_ping(first_host, second_host.IP())
        self.wait_nonzero_packet_count_flow(
            {'vlan_vid': 100, 'vlan_pcp': 1}, table_id=self._PORT_ACL_TABLE)
        tcpdump_filter = f'ether dst {second_host.MAC()}'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'ping -c3 {second_host.IP()}')], root_intf=True, packets=1)
        self.assertTrue(re.search('vlan 100, p 2,', tcpdump_txt))


class FaucetTaggedGlobalIPv4RouteTest(FaucetTaggedTest):

    def _vids():  # pylint: disable=no-method-argument,no-self-use
        return list(range(100, 148))

    def global_vid():  # pylint: disable=no-method-argument,no-self-use
        return 2047

    IPV = 4
    NETPREFIX = 24
    ETH_TYPE = IPV4_ETH
    NETNS = True
    VIDS = _vids()
    GLOBAL_VID = global_vid()
    STR_VIDS = [str(i) for i in _vids()]
    NEW_VIDS = VIDS[1:]

    @staticmethod
    def netbase(vid, host):
        return ipaddress.ip_interface(f'192.168.{vid}.{host}')

    def fping(self, macvlan_int, ipg):
        return 'fping %s -c1 -t1 -I%s %s > /dev/null 2> /dev/null' % (
            self.FPING_ARGS_SHORT, macvlan_int, ipg)

    def fib_table(self):
        return self._IPV4_FIB_TABLE

    def macvlan_ping(self, host, ipa, macvlan_int):
        return self.one_ipv4_ping(host, ipa, intf=macvlan_int)

    def run_ip(self, args):
        return f'ip -{self.IPV} {args}'

    CONFIG_GLOBAL = """
routers:
    global:
        vlans: [%s]
vlans:
%s
""" % (
        ','.join(STR_VIDS),
        '\n'.join(['\n'.join(
            ('    %u:',
             '        description: "tagged"',
             '        faucet_vips: ["192.168.%u.254/24"]')) % (i, i) for i in VIDS]))
    CONFIG = """
        global_vlan: %u
        proactive_learn_v4: True
        max_wildcard_table_size: 1024
        table_sizes:
            vlan: %u
            vip: %u
            flood: %u
        interfaces:
            %s:
                mirror: %s
            %s:
                native_vlan: 99
                tagged_vlans: [%s]
                hairpin_unicast: True
            %s:
                native_vlan: 99
                tagged_vlans: [%s]
                hairpin_unicast: True
""" % (global_vid(),
       len(STR_VIDS) * 3,   # VLAN
       len(STR_VIDS) * 2,   # VIP
       len(STR_VIDS) * 12,  # Flood
       '%(port_3)d', '%(port_1)d', '%(port_1)d',
       ','.join(STR_VIDS), '%(port_2)d', ','.join(STR_VIDS))

    def configure_mesh(self, first_host, second_host):
        hosts = (first_host, second_host)
        required_ipds = set()
        ipd_to_macvlan = {}

        for i, host in enumerate(hosts, start=1):
            setup_commands = []
            for vid in self.NEW_VIDS:
                vlan_int = f'{host.intf_root_name}.{vid}'
                macvlan_int = f'macvlan{vid}'
                ipa = self.netbase(vid, i)
                ipg = self.netbase(vid, 254)
                ipd = self.netbase(vid, 253)
                required_ipds.add(str(ipd.ip))
                ipd_to_macvlan[str(ipd.ip)] = (macvlan_int, host)
                setup_commands.extend([
                    self.run_ip(f'link add link {host.intf_root_name} name {vlan_int} type vlan id {vid}'),
                    self.run_ip(f'link set dev {vlan_int} up'),
                    self.run_ip(f'link add {macvlan_int} link {vlan_int} type macvlan mode vepa'),
                    self.run_ip(f'link set dev {macvlan_int} up'),
                    self.run_ip(f'address add {ipa.ip}/{self.NETPREFIX} dev {macvlan_int}'),
                    self.run_ip(f'route add default via {ipg.ip} table {vid}'),
                    self.run_ip(f'rule add from {ipa} table {vid} priority 100'),
                    # stimulate learning attempts for down host.
                    self.run_ip(f'neigh add {ipd.ip} lladdr {self.FAUCET_MAC} dev {macvlan_int}')])
                # next host routes via FAUCET for other host in same connected subnet
                # to cause routing to be exercised.
                for j, _ in enumerate(hosts, start=1):
                    if j != i:
                        other_ip = self.netbase(vid, j)
                        setup_commands.append(
                            self.run_ip(f'route add {other_ip} via {ipg.ip} table {vid}'))
                for ipa in (ipg.ip, ipd.ip):
                    setup_commands.append(self.fping(macvlan_int, ipa))

            self.quiet_commands(host, setup_commands)
        return required_ipds, ipd_to_macvlan

    def verify_drop_rules(self, required_ipds, ipd_to_macvlan):
        for _ in range(10):
            if not required_ipds:
                break
            drop_rules = self.get_matching_flows_on_dpid(
                self.dpid, {'dl_type': self.ETH_TYPE, 'dl_vlan': str(self.GLOBAL_VID)},
                table_id=self.fib_table(), actions=[])
            if drop_rules:
                for drop_rule in drop_rules:
                    match = drop_rule['match']
                    del match['dl_type']
                    del match['dl_vlan']
                    self.assertEqual(1, len(match))
                    ipd = list(match.values())[0].split('/')[0]
                    if ipd in required_ipds:
                        required_ipds.remove(ipd)
            for ipd in required_ipds:
                macvlan_int, host = ipd_to_macvlan[ipd]
                host.cmd(self.fping(macvlan_int, ipd))
            time.sleep(1)
        self.assertFalse(required_ipds, msg=f'no drop rules for {required_ipds}')

    def verify_routing_performance(self, first_host, second_host):
        for first_host_ip, second_host_ip in (
                (self.netbase(self.NEW_VIDS[0], 1), self.netbase(self.NEW_VIDS[0], 2)),
                (self.netbase(self.NEW_VIDS[0], 1), self.netbase(self.NEW_VIDS[-1], 2)),
                (self.netbase(self.NEW_VIDS[-1], 1), self.netbase(self.NEW_VIDS[0], 2))):
            self.verify_iperf_min(
                ((first_host, self.port_map['port_1']),
                 (second_host, self.port_map['port_2'])),
                MIN_MBPS, first_host_ip.ip, second_host_ip.ip,
                sync_counters_func=lambda: self.scapy_bcast(first_host))

    def verify_l3_mesh(self, first_host, second_host):
        for vid in self.NEW_VIDS:
            macvlan_int = f'macvlan{vid}'
            first_host_ip = self.netbase(vid, 1)
            second_host_ip = self.netbase(vid, 2)
            self.macvlan_ping(first_host, second_host_ip.ip, macvlan_int)
            self.macvlan_ping(second_host, first_host_ip.ip, macvlan_int)

    def verify_l3_hairpin(self, first_host):
        macvlan1_int = f'macvlan{self.NEW_VIDS[0]}'
        macvlan2_int = f'macvlan{self.NEW_VIDS[1]}'
        macvlan2_ip = self.netbase(self.NEW_VIDS[1], 1)
        macvlan1_gw = self.netbase(self.NEW_VIDS[0], 254)
        macvlan2_gw = self.netbase(self.NEW_VIDS[1], 254)
        netns = self.hostns(first_host)
        setup_cmds = []
        setup_cmds.extend(
            [self.run_ip(f'link set {macvlan2_int} netns {netns}')])
        for exec_cmd in (
                (self.run_ip(f'address add {macvlan2_ip.ip}/{self.NETPREFIX} dev {macvlan2_int}'),
                 self.run_ip(f'link set {macvlan2_int} up'),
                 self.run_ip(f'route add default via {macvlan2_gw.ip}'))):
            setup_cmds.append(f'ip netns exec {netns} {exec_cmd}')
        setup_cmds.append(
            self.run_ip(f'route add {macvlan2_ip} via {macvlan1_gw.ip}'))
        self.quiet_commands(first_host, setup_cmds)
        self.macvlan_ping(first_host, macvlan2_ip.ip, macvlan1_int)

    def test_tagged(self):
        first_host, second_host, mirror_host = self.hosts_name_ordered()[:3]
        required_ipds, ipd_to_macvlan = self.configure_mesh(first_host, second_host)
        self.verify_drop_rules(required_ipds, ipd_to_macvlan)
        self.verify_routing_performance(first_host, second_host)
        self.verify_l3_mesh(first_host, second_host)
        self.verify_l3_hairpin(first_host)
        self.verify_ping_mirrored(first_host, second_host, mirror_host)
        self.verify_bcast_ping_mirrored(first_host, second_host, mirror_host)


class FaucetTaggedGlobalIPv6RouteTest(FaucetTaggedGlobalIPv4RouteTest):

    IPV = 6
    NETPREFIX = 112
    ETH_TYPE = IPV6_ETH

    def _vids():  # pylint: disable=no-method-argument,no-self-use
        return list(range(100, 103))

    def global_vid():  # pylint: disable=no-method-argument,no-self-use
        return 2047

    VIDS = _vids()
    GLOBAL_VID = global_vid()
    STR_VIDS = [str(i) for i in _vids()]
    NEW_VIDS = VIDS[1:]

    def netbase(self, vid, host):
        return ipaddress.ip_interface(f'fc00::{vid}:{host}')

    def fib_table(self):
        return self._IPV6_FIB_TABLE

    def fping(self, macvlan_int, ipg):
        return 'fping6 %s -c1 -t1 -I%s %s > /dev/null 2> /dev/null' % (
            self.FPING_ARGS_SHORT, macvlan_int, ipg)

    def macvlan_ping(self, host, ipa, macvlan_int):
        return self.one_ipv6_ping(host, ipa, intf=macvlan_int)

    def run_ip(self, args):
        return f'ip -{self.IPV} {args}'

    CONFIG_GLOBAL = """
routers:
    global:
        vlans: [%s]
vlans:
%s
""" % (
        ','.join(STR_VIDS),
        '\n'.join(['\n'.join(
            ('    %u:',
             '        description: "tagged"',
             '        faucet_vips: ["fc00::%u:254/112"]')) % (i, i) for i in VIDS]))
    CONFIG = """
        global_vlan: %u
        proactive_learn_v6: True
        max_wildcard_table_size: 512
        table_sizes:
            vlan: 256
            vip: 128
            flood: 384
        interfaces:
            %s:
                mirror: %s
            %s:
                native_vlan: 99
                tagged_vlans: [%s]
                hairpin_unicast: True
            %s:
                native_vlan: 99
                tagged_vlans: [%s]
                hairpin_unicast: True
""" % (global_vid(), '%(port_3)d', '%(port_1)d', '%(port_1)d',
       ','.join(STR_VIDS), '%(port_2)d', ','.join(STR_VIDS))


class FaucetTaggedScaleTest(FaucetTaggedTest):

    def _vids():  # pylint: disable=no-method-argument,no-self-use
        return list(range(100, 148))

    VIDS = _vids()
    STR_VIDS = [str(i) for i in _vids()]
    NEW_VIDS = VIDS[1:]

    CONFIG_GLOBAL = """
vlans:
""" + '\n'.join(['\n'.join(
        ('    %u:',
         '        description: "tagged"')) % i for i in VIDS])
    CONFIG = """
        interfaces:
            %s:
                tagged_vlans: [%s]
            %s:
                tagged_vlans: [%s]
            %s:
                tagged_vlans: [%s]
            %s:
                tagged_vlans: [%s]
""" % ('%(port_1)d', ','.join(STR_VIDS),
       '%(port_2)d', ','.join(STR_VIDS),
       '%(port_3)d', ','.join(STR_VIDS),
       '%(port_4)d', ','.join(STR_VIDS))

    def test_tagged(self):
        self.ping_all_when_learned()
        for host in self.hosts_name_ordered():
            setup_commands = []
            for vid in self.NEW_VIDS:
                vlan_int = f'{host.intf_root_name}.{vid}'
                setup_commands.extend([
                    f'ip link add link {host.intf_root_name} name {vlan_int} type vlan id {vid}',
                    f'ip link set dev {vlan_int} up'])
            self.quiet_commands(host, setup_commands)
        for host in self.hosts_name_ordered():
            rdisc6_commands = []
            for vid in self.NEW_VIDS:
                vlan_int = f'{host.intf_root_name}.{vid}'
                rdisc6_commands.append(
                    'rdisc6 -r2 -w1 -q %s 2> /dev/null' % vlan_int)
            self.quiet_commands(host, rdisc6_commands)
        for vlan in self.NEW_VIDS:
            vlan_int = f'{host.intf_root_name}.{vid}'
            for _ in range(3):
                for host in self.hosts_name_ordered():
                    self.quiet_commands(
                        host,
                        ['rdisc6 -r2 -w1 -q %s 2> /dev/null' % vlan_int])
                vlan_hosts_learned = self.scrape_prometheus_var(
                    'vlan_hosts_learned', {'vlan': str(vlan)})
                if vlan_hosts_learned == len(self.hosts_name_ordered()):
                    break
                time.sleep(1)
            self.assertGreater(
                vlan_hosts_learned, 1,
                msg=f'not all VLAN {vlan} hosts learned ({vlan_hosts_learned})')


class FaucetTaggedBroadcastTest(FaucetTaggedTest):

    def test_tagged(self):
        super().test_tagged()
        self.verify_broadcast()
        self.verify_no_bcast_to_self()


class FaucetTaggedExtLoopProtectTest(FaucetTaggedTest):

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                loop_protect_external: True
            %(port_2)d:
                tagged_vlans: [100]
                loop_protect_external: True
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        ext_port1, ext_port2, int_port1, int_port2 = self.hosts_name_ordered()
        self.verify_broadcast((ext_port1, ext_port2), False)
        self.verify_broadcast((int_port1, int_port2), True)
        self.verify_unicast((int_port1, int_port2), True)


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
            %(port_2)d:
                native_vlan: 200
                tagged_vlans: [100]
            %(port_3)d:
                native_vlan: 200
                tagged_vlans: [100]
            %(port_4)d:
                native_vlan: 200
                tagged_vlans: [100]
"""

    def test_tagged(self):
        self.ping_all_when_learned()
        native_ips = [
            ipaddress.ip_interface(f'10.99.99.{i + 1}/24') for i in range(len(self.hosts_name_ordered()))]
        for native_ip, host in zip(native_ips, self.hosts_name_ordered()):
            self.host_ipv4_alias(host, native_ip, intf=host.intf_root_name)
        for own_native_ip, host in zip(native_ips, self.hosts_name_ordered()):
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
                mirror: %(port_3)d
                force_port_vlan: 1
                output:
                    swap_vid: 101
                allow: 1
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [101]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
    """

    def test_tagged(self):
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]

        def test_acl(tcpdump_host, tcpdump_filter):
            tcpdump_txt = self.tcpdump_helper(
                tcpdump_host, tcpdump_filter, [
                    lambda: first_host.cmd(
                        f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                    lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
                root_intf=True)
            self.assertTrue(re.search(
                f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
            self.assertTrue(re.search(
                tcpdump_filter, tcpdump_txt))

        # Saw swapped VID on second host
        test_acl(second_host, 'vlan 101')
        # Saw original VID on mirror host
        test_acl(third_host, 'vlan 100')


class FaucetTaggedOrderedSwapVidMirrorTest(FaucetTaggedTest):

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
                mirror: %(port_3)d
                force_port_vlan: 1
                output:
                    - swap_vid: 101
                allow: 1
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [101]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
    """

    def test_tagged(self):
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]

        def test_acl(tcpdump_host, tcpdump_filter):
            tcpdump_txt = self.tcpdump_helper(
                tcpdump_host, tcpdump_filter, [
                    lambda: first_host.cmd(
                        f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                    lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
                root_intf=True)
            self.assertTrue(re.search(
                f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
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
                    port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [101]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the swapped VLAN VID
        tcpdump_filter = 'vlan 101'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            root_intf=True)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
        self.assertTrue(re.search(
            'vlan 101', tcpdump_txt))


class FaucetTaggedSwapVidOrderedOutputTest(FaucetTaggedTest):

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
                    - swap_vid: 101
                    - port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [101]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expected to see the swapped VLAN VID
        tcpdump_filter = 'vlan 101'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            root_intf=True)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))
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
                    port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        tcpdump_filter = 'not vlan and icmp and ether dst 06:06:06:06:06:06'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(
                    ' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            packets=10, root_intf=True)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))


class FaucetTaggedPopVlansOrderedOutputTest(FaucetTaggedTest):

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
                    - set_fields:
                        - eth_dst: "06:06:06:06:06:06"
                    - pop_vlans: 1
                    - port: %(port_2)d
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_tagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        tcpdump_filter = 'not vlan and icmp and ether dst 06:06:06:06:06:06'
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} 01:02:03:04:05:06'),
                lambda: first_host.cmd(
                    ' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            packets=10, root_intf=True)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))


class FaucetTaggedIPv4ControlPlaneTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "tagged"
        faucet_vips: ["10.0.0.254/24"]
"""

    CONFIG = """
        max_resolve_backoff_time: 1
""" + CONFIG_TAGGED_BOILER

    def test_ping_controller(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
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
""" + CONFIG_TAGGED_BOILER

    def test_ping_controller(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
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
            dl_type: %u
            vlan_vid: 100
            ip_proto: 58
            icmpv6_type: 135
            ipv6_nd_target: "fc00::1:2"
            actions:
                output:
                    port: %s
        - rule:
            actions:
                allow: 1
vlans:
    100:
        description: "tagged"
        faucet_vips: ["fc00::1:254/112"]
""" % (IPV6_ETH, '%(port_2)d')

    CONFIG = """
        max_resolve_backoff_time: 1
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_icmpv6_acl_match(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        self.wait_nonzero_packet_count_flow(
            {'dl_type': IPV6_ETH, 'ip_proto': 58, 'icmpv6_type': 135,
             'ipv6_nd_target': 'fc00::1:2'}, table_id=self._PORT_ACL_TABLE)


class FaucetTaggedICMPv6OrderedACLTest(FaucetTaggedTest):

    CONFIG_GLOBAL = """
acls:
    1:
        - rule:
            dl_type: %u
            vlan_vid: 100
            ip_proto: 58
            icmpv6_type: 135
            ipv6_nd_target: "fc00::1:2"
            actions:
                output:
                    - port: %s
        - rule:
            actions:
                allow: 1
vlans:
    100:
        description: "tagged"
        faucet_vips: ["fc00::1:254/112"]
""" % (IPV6_ETH, '%(port_2)d')

    CONFIG = """
        max_resolve_backoff_time: 1
        interfaces:
            %(port_1)d:
                tagged_vlans: [100]
                acl_in: 1
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                tagged_vlans: [100]
"""

    def test_icmpv6_acl_match(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        self.one_ipv6_ping(first_host, 'fc00::1:2')
        self.wait_nonzero_packet_count_flow(
            {'dl_type': IPV6_ETH, 'ip_proto': 58, 'icmpv6_type': 135,
             'ipv6_nd_target': 'fc00::1:2'}, table_id=self._PORT_ACL_TABLE)


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
            %(port_2)d:
                tagged_vlans: [100]
            %(port_3)d:
                tagged_vlans: [100]
            %(port_4)d:
                native_vlan: 200
"""

    def test_tagged(self):
        self._enable_event_log()
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddress.ip_interface('10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface('10.0.2.1/24')
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
        self.wait_until_matching_lines_from_file(
            r'.+L3_LEARN.+10.0.0.[12].+', self.event_log)


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
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v4: True
""" + CONFIG_TAGGED_BOILER

    def test_tagged(self):
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_alias_ip = ipaddress.ip_interface('10.0.0.99/24')
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
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v6: True
""" + CONFIG_TAGGED_BOILER

    def test_tagged(self):
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_alias_ip = ipaddress.ip_interface('fc00::1:99/64')
        faucet_vip_ip = ipaddress.ip_interface('fc00::1:3/126')
        first_host_alias_host_ip = ipaddress.ip_interface(
            ipaddress.ip_network(first_host_alias_ip.ip))
        self.add_host_ipv6_address(first_host, ipaddress.ip_interface('fc00::1:1/64'))
        # We use a narrower mask to force second_host to use the /128 route,
        # since otherwise it would realize :99 is directly connected via ND and send direct.
        self.add_host_ipv6_address(second_host, ipaddress.ip_interface('fc00::1:2/126'))
        self.add_host_ipv6_address(first_host, first_host_alias_ip)
        self.add_host_route(second_host, first_host_alias_host_ip, faucet_vip_ip.ip)
        self.one_ipv6_ping(second_host, first_host_alias_ip.ip)
        self.assertGreater(
            self.scrape_prometheus_var(
                'vlan_neighbors', {'ipv': '6', 'vlan': '100'}),
            1)


class FaucetUntaggedIPv4GlobalInterVLANRouteTest(FaucetUntaggedTest):

    NUM_FAUCET_CONTROLLERS = 1

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["10.100.0.254/24"]
    200:
        faucet_vips: ["10.200.0.254/24"]
        faucet_mac: "%s"
""" % FAUCET_MAC2 + """
routers:
    global:
        vlans: [100, 200]
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["127.0.0.1", "::1"]
            neighbor_addresses: ["127.0.0.1", "::1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        global_vlan: 300
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v4: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: 200
            %(port_3)d:
                native_vlan: 200
            %(port_4)d:
                native_vlan: 200
"""

    exabgp_peer_conf = """
    static {
      route 10.99.99.0/24 next-hop 10.200.0.1 local-preference 100;
      route 10.0.5.0/24 next-hop 127.0.0.1;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf(
            mininet_test_util.LOCALHOST, self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface('10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface('10.200.0.254/24')
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host.setIP(str(first_host_ip.ip), prefixLen=24)
        second_host.setIP(str(second_host_ip.ip), prefixLen=24)
        self.add_host_route(first_host, second_host_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)
        self.assertEqual(
            self._ip_neigh(first_host, first_faucet_vip.ip, 4), self.FAUCET_MAC)
        self.assertEqual(
            self._ip_neigh(second_host, second_faucet_vip.ip, 4), self.FAUCET_MAC2)
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv4Network('10.99.99.0/24'), vlan_vid=300)
        self.verify_invalid_bgp_route(r'.+10.0.5.0\/24.+because nexthop not in VLAN.+')


class FaucetUntaggedIPv4InterVLANRouteTest(FaucetUntaggedTest):

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["10.100.0.254/24", "169.254.1.1/24"]
    vlanb:
        vid: 200
        faucet_vips: ["10.200.0.254/24", "169.254.2.1/24"]
        faucet_mac: "%s"
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v4: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: vlanb
            %(port_3)d:
                native_vlan: vlanb
            %(port_4)d:
                native_vlan: vlanb
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface('10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface('10.200.0.254/24')
        first_host, second_host = self.hosts_name_ordered()[:2]
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


class FaucetUntaggedPortSwapIPv4InterVLANRouteTest(FaucetUntaggedTest):

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    vlana:
        vid: 100
        faucet_vips: ["10.100.0.254/24", "169.254.1.1/24"]
    vlanb:
        vid: 200
        faucet_vips: ["10.200.0.254/24", "169.254.2.1/24"]
        faucet_mac: "%s"
routers:
    router-1:
        vlans: [vlana, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v4: True
        interfaces:
            %(port_1)d:
                native_vlan: vlana
            %(port_2)d:
                native_vlan: vlanb
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface('10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface('10.200.0.254/24')
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]

        def test_connectivity(host_a, host_b):
            host_a.setIP(str(first_host_ip.ip), prefixLen=24)
            host_b.setIP(str(second_host_ip.ip), prefixLen=24)
            self.add_host_route(host_a, second_host_ip, first_faucet_vip.ip)
            self.add_host_route(host_b, first_host_ip, second_faucet_vip.ip)
            self.one_ipv4_ping(host_a, second_host_ip.ip)
            self.one_ipv4_ping(host_b, first_host_ip.ip)
            self.assertEqual(
                self._ip_neigh(host_a, first_faucet_vip.ip, 4), self.FAUCET_MAC)
            self.assertEqual(
                self._ip_neigh(host_b, second_faucet_vip.ip, 4), self.FAUCET_MAC2)

        test_connectivity(first_host, second_host)

        # Delete port 1, add port 3
        self.change_port_config(
            self.port_map['port_1'], None, None,
            restart=False, cold_start=False)
        self.add_port_config(
            self.port_map['port_3'], {'native_vlan': 'vlana'},
            restart=True, cold_start=True)

        test_connectivity(third_host, second_host)


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
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        arp_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        max_host_fib_retry_count: 2
        proactive_learn_v4: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: vlanb
            %(port_3)d:
                native_vlan: vlanb
            %(port_4)d:
                native_vlan: vlanb
"""

    def test_untagged(self):
        first_host_ip = ipaddress.ip_interface('10.100.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.100.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.200.0.1/24')
        second_faucet_vip = ipaddress.ip_interface('10.200.0.254/24')
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host.setIP(str(first_host_ip.ip), prefixLen=24)
        second_host.setIP(str(second_host_ip.ip), prefixLen=24)
        self.add_host_route(first_host, second_host_ip, first_faucet_vip.ip)
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)
        second_host.cmd(f'ifconfig {second_host.defaultIntf().name} down')
        expired_re = r'.+expiring dead route %s.+' % second_host_ip.ip
        self.wait_until_matching_lines_from_faucet_log_files(expired_re)
        second_host.cmd(f'ifconfig {second_host.defaultIntf().name} up')
        self.add_host_route(second_host, first_host_ip, second_faucet_vip.ip)
        self.one_ipv4_ping(second_host, first_host_ip.ip)
        self.one_ipv4_ping(first_host, second_host_ip.ip)


class FaucetUntaggedIPv6InterVLANRouteTest(FaucetUntaggedTest):

    FAUCET_MAC2 = '0e:00:00:00:00:02'

    CONFIG_GLOBAL = """
vlans:
    100:
        faucet_vips: ["fc00::1:254/112", "fe80::1:254/112"]
    vlanb:
        vid: 200
        faucet_vips: ["fc01::1:254/112", "fe80::2:254/112"]
        faucet_mac: "%s"
routers:
    router-1:
        vlans: [100, vlanb]
""" % FAUCET_MAC2

    CONFIG = """
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        proactive_learn_v6: True
        interfaces:
            %(port_1)d:
                native_vlan: 100
            %(port_2)d:
                native_vlan: vlanb
            %(port_3)d:
                native_vlan: vlanb
            %(port_4)d:
                native_vlan: vlanb
"""

    def test_untagged(self):
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddress.ip_interface('fc00::1:1/64')
        second_host_net = ipaddress.ip_interface('fc01::1:1/64')
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
            %(port_2)d:
                native_vlan: 200
            %(port_3)d:
                native_vlan: 300
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        # 10.99.0.1 is on b2, and 10.99.0.2 is on b3
        # we want to route 10.99.0.0/24 to b2, but we want
        # want to PBR 10.99.0.2/32 to b3.
        first_host_ip = ipaddress.ip_interface('10.0.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.0.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.20.0.2/24')
        second_faucet_vip = ipaddress.ip_interface('10.20.0.254/24')
        third_host_ip = ipaddress.ip_interface('10.30.0.3/24')
        third_faucet_vip = ipaddress.ip_interface('10.30.0.254/24')
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]
        remote_ip = ipaddress.ip_interface('10.99.0.1/24')
        remote_ip2 = ipaddress.ip_interface('10.99.0.2/24')
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
            second_host.MAC(), ipaddress.IPv4Network('10.99.0.0/24'), vlan_vid=200)
        self.wait_for_route_as_flow(
            third_host.MAC(), ipaddress.IPv4Network('10.99.0.0/24'), vlan_vid=300)
        # verify b1 can reach 10.99.0.1 and .2 on b2 and b3 respectively.
        self.one_ipv4_ping(first_host, remote_ip.ip)
        self.one_ipv4_ping(first_host, remote_ip2.ip)


class FaucetUntaggedIPv4PolicyRouteOrdereredTest(FaucetUntaggedTest):

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
                    - swap_vid: 300
        - rule:
            vlan_vid: 100
            dl_type: 0x800
            nw_dst: "10.99.0.0/24"
            actions:
                allow: 1
                output:
                    - swap_vid: 200
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
            %(port_2)d:
                native_vlan: 200
            %(port_3)d:
                native_vlan: 300
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        # 10.99.0.1 is on b2, and 10.99.0.2 is on b3
        # we want to route 10.99.0.0/24 to b2, but we want
        # want to PBR 10.99.0.2/32 to b3.
        first_host_ip = ipaddress.ip_interface('10.0.0.1/24')
        first_faucet_vip = ipaddress.ip_interface('10.0.0.254/24')
        second_host_ip = ipaddress.ip_interface('10.20.0.2/24')
        second_faucet_vip = ipaddress.ip_interface('10.20.0.254/24')
        third_host_ip = ipaddress.ip_interface('10.30.0.3/24')
        third_faucet_vip = ipaddress.ip_interface('10.30.0.254/24')
        first_host, second_host, third_host = self.hosts_name_ordered()[:3]
        remote_ip = ipaddress.ip_interface('10.99.0.1/24')
        remote_ip2 = ipaddress.ip_interface('10.99.0.2/24')
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
            second_host.MAC(), ipaddress.IPv4Network('10.99.0.0/24'), vlan_vid=200)
        self.wait_for_route_as_flow(
            third_host.MAC(), ipaddress.IPv4Network('10.99.0.0/24'), vlan_vid=300)
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
""" + CONFIG_BOILER_UNTAGGED

    def test_untagged(self):
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddress.ip_interface('10.0.0.1/24')
        second_host_net = ipaddress.ip_interface('172.16.0.1/24')
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
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_untagged(self):
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_net = ipaddress.ip_interface('fc00::1:1/64')
        second_host_net = ipaddress.ip_interface('fc01::1:1/64')
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

    NUM_FAUCET_CONTROLLERS = 1

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["::1"]
            neighbor_addresses: ["::1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_peer_conf = """
    static {
      route ::/0 next-hop fc00::1:1 local-preference 100;
    }
"""

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1', self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        self.assertEqual(self.NUM_FAUCET_CONTROLLERS, 1)
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.add_host_ipv6_address(first_host, 'fc00::1:1/112')
        self.add_host_ipv6_address(second_host, 'fc00::1:2/112')
        first_host_alias_ip = ipaddress.ip_interface('fc00::50:1/112')
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

    NUM_FAUCET_CONTROLLERS = 1

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
        faucet_vips: ["fc00::1:254/112"]
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["::1"]
            neighbor_addresses: ["::1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_peer_conf = """
    static {
      route fc00::10:0/112 next-hop fc00::1:1 local-preference 100;
      route fc00::20:0/112 next-hop fc00::1:2 local-preference 100;
      route fc00::30:0/112 next-hop fc00::1:2 local-preference 100;
      route fc00::40:0/112 next-hop fc00::1:254;
      route fc00::50:0/112 next-hop fc00::2:2;
    }
"""
    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1', self.exabgp_peer_conf)
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        self.assertEqual(self.NUM_FAUCET_CONTROLLERS, 1)
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.wait_bgp_up('::1', 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}),
            0)
        self.wait_exabgp_sent_updates(self.exabgp_log)
        self.verify_invalid_bgp_route(r'.+fc00::40:0\/112.+cannot be us$')
        self.verify_ipv6_routing_mesh()
        self.flap_all_switch_ports()
        self.verify_ipv6_routing_mesh()
        for host in first_host, second_host:
            self.one_ipv6_controller_ping(host)
        self.verify_traveling_dhcp_mac()


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
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[:2]
        first_host_ip = ipaddress.ip_interface('fc00::10:2/112')
        first_host_ctrl_ip = ipaddress.ip_address('fc00::10:1')
        second_host_ip = ipaddress.ip_interface('fc00::20:2/112')
        second_host_ctrl_ip = ipaddress.ip_address('fc00::20:1')
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

    NUM_FAUCET_CONTROLLERS = 1

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
routers:
    router1:
        bgp:
            as: 1
            connect_mode: "passive"
            port: %(bgp_port)d
            routerid: "1.1.1.1"
            server_addresses: ["::1"]
            neighbor_addresses: ["::1"]
            vlan: 100
""" + """
            neighbor_as: %u
""" % PEER_BGP_AS

    CONFIG = """
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_BOILER_UNTAGGED

    exabgp_log = None
    exabgp_err = None
    config_ports = {'bgp_port': None}

    def post_start_net(self):
        exabgp_conf = self.get_exabgp_conf('::1')
        self.exabgp_log, self.exabgp_err = self.start_exabgp(exabgp_conf)

    def test_untagged(self):
        self.verify_ipv6_routing_mesh()
        second_host = self.hosts_name_ordered()[1]
        self.flap_all_switch_ports()
        self.wait_for_route_as_flow(
            second_host.MAC(), ipaddress.IPv6Network('fc00::30:0/112'))
        self.verify_ipv6_routing_mesh()
        self.wait_bgp_up('::1', 100, self.exabgp_log, self.exabgp_err)
        self.assertGreater(
            self.scrape_prometheus_var(
                'bgp_neighbor_routes', {'ipv': '6', 'vlan': '100'}, default=0),
            0)
        updates = self.exabgp_updates(self.exabgp_log)
        for route_string in (
                'fc00::1:0/112 next-hop fc00::1:254',
                'fc00::10:0/112 next-hop fc00::1:1',
                'fc00::20:0/112 next-hop fc00::1:2',
                'fc00::30:0/112 next-hop fc00::1:2'):
            self.assertTrue(re.search(route_string, updates), msg=updates)


class FaucetUntaggedRestBcastIPv6RouteTest(FaucetUntaggedIPv6RouteTest):

    CONFIG = """
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
        interfaces:
            %(port_1)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_2)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_3)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
            %(port_4)d:
                native_vlan: 100
                restricted_bcast_arpnd: true
"""


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
        nd_neighbor_timeout: 2
        max_resolve_backoff_time: 1
""" + CONFIG_TAGGED_BOILER

    def test_tagged(self):
        """Test IPv6 routing works."""
        host_pair = self.hosts_name_ordered()[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddress.ip_interface('fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface('fc00::1:2/112')
        first_host_routed_ip = ipaddress.ip_interface('fc00::10:1/112')
        second_host_routed_ip = ipaddress.ip_interface('fc00::20:1/112')
        for _coldstart in range(2):
            for _swaps in range(5):
                self.verify_ipv6_routing_pair(
                    first_host, first_host_ip, first_host_routed_ip,
                    second_host, second_host_ip, second_host_routed_ip)
                self.swap_host_macs(first_host, second_host)
            self.coldstart_conf()


class FaucetGroupTableTest(FaucetUntaggedTest):

    CONFIG = """
        group_table: True
""" + CONFIG_BOILER_UNTAGGED

    def test_group_exist(self):
        self.assertEqual(
            100,
            self.get_group_id_for_matching_flow(
                {'dl_vlan': '100', 'dl_dst': 'ff:ff:ff:ff:ff:ff'},
                table_id=self._FLOOD_TABLE))


class FaucetTaggedGroupTableTest(FaucetTaggedTest):

    CONFIG = """
        group_table: True
""" + CONFIG_TAGGED_BOILER

    def test_group_exist(self):
        self.assertEqual(
            100,
            self.get_group_id_for_matching_flow(
                {'dl_vlan': '100', 'dl_dst': 'ff:ff:ff:ff:ff:ff'},
                table_id=self._FLOOD_TABLE))


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
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        first_host.setMAC('0e:0d:00:00:00:99')
        self.retry_net_ping(hosts=(first_host, second_host))
        self.wait_nonzero_packet_count_flow(
            {'dl_src': '0e:0d:00:00:00:00/ff:ff:00:00:00:00'},
            table_id=self._PORT_ACL_TABLE)


class FaucetDestRewriteTest(FaucetUntaggedTest):

    def override_mac():  # pylint: disable=no-method-argument,no-self-use
        return '0e:00:00:00:00:02'

    OVERRIDE_MAC = override_mac()

    def rewrite_mac():  # pylint: disable=no-method-argument,no-self-use
        return '0e:00:00:00:00:03'

    REWRITE_MAC = rewrite_mac()

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            dl_dst: "%s"
            actions:
                allow: 1
                output:
                    set_fields:
                        - eth_dst: "%s"
        - rule:
            actions:
                allow: 1
""" % (override_mac(), rewrite_mac())
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expect to see the rewritten mac address.
        tcpdump_filter = (f'icmp and ether dst {self.REWRITE_MAC}')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} {self.OVERRIDE_MAC}'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            timeout=5, packets=1)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))

    def verify_dest_rewrite(self, source_host, overridden_host, rewrite_host, tcpdump_host):
        overridden_host.setMAC(self.OVERRIDE_MAC)
        rewrite_host.setMAC(self.REWRITE_MAC)
        rewrite_host.cmd(f'arp -s {overridden_host.IP()} {overridden_host.MAC()}')
        rewrite_host.cmd(' '.join((self.FPINGS_ARGS_ONE, overridden_host.IP())))
        self.wait_until_matching_flow(
            {'dl_dst': self.REWRITE_MAC},
            table_id=self._ETH_DST_TABLE,
            actions=[f'OUTPUT:{self.port_map["port_3"]}'])
        tcpdump_filter = f'icmp and ether src {source_host.MAC()} and ether dst {rewrite_host.MAC()}'
        tcpdump_txt = self.tcpdump_helper(
            tcpdump_host, tcpdump_filter, [
                lambda: source_host.cmd(
                    f'arp -s {rewrite_host.IP()} {overridden_host.MAC()}'),
                # this will fail if no reply
                lambda: self.one_ipv4_ping(
                    source_host, rewrite_host.IP(), require_host_learned=False)],
            timeout=3, packets=1)
        # ping from h1 to h2.mac should appear in third host, and not second host, as
        # the acl should rewrite the dst mac.
        self.assertFalse(re.search(
            f'{rewrite_host.IP()}: ICMP echo request', tcpdump_txt))

    def test_switching(self):
        """Tests that a acl can rewrite the destination mac address,
           and the packet will only go out the port of the new mac.
           (Continues through faucet pipeline)
        """
        source_host, overridden_host, rewrite_host = self.hosts_name_ordered()[0:3]
        self.verify_dest_rewrite(
            source_host, overridden_host, rewrite_host, overridden_host)


class FaucetDestRewriteOrderedTest(FaucetUntaggedTest):

    def override_mac():  # pylint: disable=no-method-argument,no-self-use
        return '0e:00:00:00:00:02'

    OVERRIDE_MAC = override_mac()

    def rewrite_mac():  # pylint: disable=no-method-argument,no-self-use
        return '0e:00:00:00:00:03'

    REWRITE_MAC = rewrite_mac()

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            dl_dst: "%s"
            actions:
                allow: 1
                output:
                    - set_fields:
                        - eth_dst: "%s"
        - rule:
            actions:
                allow: 1
""" % (override_mac(), rewrite_mac())
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
"""

    def test_untagged(self):
        first_host, second_host = self.hosts_name_ordered()[0:2]
        # we expect to see the rewritten mac address.
        tcpdump_filter = (f'icmp and ether dst {self.REWRITE_MAC}')
        tcpdump_txt = self.tcpdump_helper(
            second_host, tcpdump_filter, [
                lambda: first_host.cmd(
                    f'arp -s {second_host.IP()} {self.OVERRIDE_MAC}'),
                lambda: first_host.cmd(' '.join((self.FPINGS_ARGS_ONE, second_host.IP())))],
            timeout=5, packets=1)
        self.assertTrue(re.search(
            f'{second_host.IP()}: ICMP echo request', tcpdump_txt))

    def verify_dest_rewrite(self, source_host, overridden_host, rewrite_host, tcpdump_host):
        overridden_host.setMAC(self.OVERRIDE_MAC)
        rewrite_host.setMAC(self.REWRITE_MAC)
        rewrite_host.cmd(f'arp -s {overridden_host.IP()} {overridden_host.MAC()}')
        rewrite_host.cmd(' '.join((self.FPINGS_ARGS_ONE, overridden_host.IP())))
        self.wait_until_matching_flow(
            {'dl_dst': self.REWRITE_MAC},
            table_id=self._ETH_DST_TABLE,
            actions=[f'OUTPUT:{self.port_map["port_3"]}'])
        tcpdump_filter = f'icmp and ether src {source_host.MAC()} and ether dst {rewrite_host.MAC()}'
        tcpdump_txt = self.tcpdump_helper(
            tcpdump_host, tcpdump_filter, [
                lambda: source_host.cmd(
                    f'arp -s {rewrite_host.IP()} {overridden_host.MAC()}'),
                # this will fail if no reply
                lambda: self.one_ipv4_ping(
                    source_host, rewrite_host.IP(), require_host_learned=False)],
            timeout=3, packets=1)
        # ping from h1 to h2.mac should appear in third host, and not second host, as
        # the acl should rewrite the dst mac.
        self.assertFalse(re.search(
            f'{rewrite_host.IP()}: ICMP echo request', tcpdump_txt))

    def test_switching(self):
        """Tests that a acl can rewrite the destination mac address,
           and the packet will only go out the port of the new mac.
           (Continues through faucet pipeline)
        """
        source_host, overridden_host, rewrite_host = self.hosts_name_ordered()[0:3]
        self.verify_dest_rewrite(
            source_host, overridden_host, rewrite_host, overridden_host)


class FaucetSetFieldsTest(FaucetUntaggedTest):
    # A generic test to verify that a flow will set fields specified for
    # matching packets
    OUTPUT_MAC = '0f:00:12:23:48:03'
    SRC_MAC = '0f:12:00:00:00:ff'

    IP_DSCP_VAL = 46
    # this is the converted DSCP value that is displayed
    NW_TOS_VAL = 184
    IPV4_SRC_VAL = "192.0.2.0"
    IPV4_DST_VAL = "198.51.100.0"
    # ICMP echo request
    ICMPV4_TYPE_VAL = 8
    UDP_SRC_PORT = 68
    UDP_DST_PORT = 67

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            eth_type: 0x0800
            actions:
                allow: 1
                output:
                    set_fields:
                        - ipv4_src: '%s'
                        - ipv4_dst: '%s'
                        - ip_dscp: %d
        - rule:
            eth_type: 0x0800
            ip_proto: 1
            actions:
                allow: 1
                output:
                    set_fields:
                        - icmpv4_type: %d
""" % (IPV4_SRC_VAL, IPV4_DST_VAL, IP_DSCP_VAL, ICMPV4_TYPE_VAL)
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
    """

    def test_set_fields_generic_udp(self):
        # Send a basic UDP packet through the faucet pipeline and verify that
        # the expected fields were updated via tcpdump output
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.OUTPUT_MAC)

        # scapy command to create and send a UDP packet
        scapy_pkt = self.scapy_base_udp(
            self.SRC_MAC, source_host.defaultIntf(), source_host.IP(),
            dest_host.IP(), self.UDP_DST_PORT, self.UDP_SRC_PORT,
            dst=self.OUTPUT_MAC)

        tcpdump_filter = f"ether dst {self.OUTPUT_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)

        # verify that the packet we've received on the dest_host has the
        # overwritten values
        self.assertTrue(
            re.search("%s.%s > %s.%s" % (self.IPV4_SRC_VAL, self.UDP_SRC_PORT,
                                         self.IPV4_DST_VAL, self.UDP_DST_PORT),
                      tcpdump_txt))
        # check the packet's converted dscp value
        self.assertTrue(re.search(f"tos {hex(self.NW_TOS_VAL)}", tcpdump_txt))

    def test_set_fields_icmp(self):
        # Send a basic ICMP packet through the faucet pipeline and verify that
        # the expected fields were updated via tcpdump output
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.OUTPUT_MAC)

        # scapy command to create and send an ICMP packet
        scapy_pkt = self.scapy_icmp(
            self.SRC_MAC, source_host.defaultIntf(), source_host.IP(),
            dest_host.IP(), dst=self.OUTPUT_MAC)

        tcpdump_filter = f"ether dst {self.OUTPUT_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)

        # verify that the packet we've received on the dest_host has been
        # overwritten to be an ICMP echo request
        self.assertTrue(re.search("ICMP echo request", tcpdump_txt))

    def test_untagged(self):
        pass


class FaucetOrderedSetFieldsTest(FaucetUntaggedTest):
    # A generic test to verify that a flow will set fields specified for
    # matching packets
    OUTPUT_MAC = '0f:00:12:23:48:03'
    SRC_MAC = '0f:12:00:00:00:ff'

    IP_DSCP_VAL = 46
    # this is the converted DSCP value that is displayed
    NW_TOS_VAL = 184
    IPV4_SRC_VAL = "192.0.2.0"
    IPV4_DST_VAL = "198.51.100.0"
    # ICMP echo request
    ICMPV4_TYPE_VAL = 8
    UDP_SRC_PORT = 68
    UDP_DST_PORT = 67

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            eth_type: 0x0800
            actions:
                allow: 1
                output:
                    - set_fields:
                        - ipv4_src: '%s'
                        - ipv4_dst: '%s'
                        - ip_dscp: %d
        - rule:
            eth_type: 0x0800
            ip_proto: 1
            actions:
                allow: 1
                output:
                    - set_fields:
                        - icmpv4_type: %d
""" % (IPV4_SRC_VAL, IPV4_DST_VAL, IP_DSCP_VAL, ICMPV4_TYPE_VAL)
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
    """

    def test_set_fields_generic_udp(self):
        # Send a basic UDP packet through the faucet pipeline and verify that
        # the expected fields were updated via tcpdump output
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.OUTPUT_MAC)

        # scapy command to create and send a UDP packet
        scapy_pkt = self.scapy_base_udp(
            self.SRC_MAC, source_host.defaultIntf(), source_host.IP(),
            dest_host.IP(), self.UDP_DST_PORT, self.UDP_SRC_PORT,
            dst=self.OUTPUT_MAC)

        tcpdump_filter = f"ether dst {self.OUTPUT_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)

        # verify that the packet we've received on the dest_host has the
        # overwritten values
        self.assertTrue(
            re.search("%s.%s > %s.%s" % (self.IPV4_SRC_VAL, self.UDP_SRC_PORT,
                                         self.IPV4_DST_VAL, self.UDP_DST_PORT),
                      tcpdump_txt))
        # check the packet's converted dscp value
        self.assertTrue(re.search(f"tos {hex(self.NW_TOS_VAL)}", tcpdump_txt))

    def test_set_fields_icmp(self):
        # Send a basic ICMP packet through the faucet pipeline and verify that
        # the expected fields were updated via tcpdump output
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.OUTPUT_MAC)

        # scapy command to create and send an ICMP packet
        scapy_pkt = self.scapy_icmp(
            self.SRC_MAC, source_host.defaultIntf(), source_host.IP(),
            dest_host.IP(), dst=self.OUTPUT_MAC)

        tcpdump_filter = f"ether dst {self.OUTPUT_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)

        # verify that the packet we've received on the dest_host has been
        # overwritten to be an ICMP echo request
        self.assertTrue(re.search("ICMP echo request", tcpdump_txt))

    def test_untagged(self):
        pass


class FaucetDscpMatchTest(FaucetUntaggedTest):
    # Match all packets with this IP_DSP and eth_type, based on the ryu API def
    # e.g {"ip_dscp": 3, "eth_type": 2048}
    # Note: the ip_dscp field is translated to nw_tos in OpenFlow 1.0:
    # see https://tools.ietf.org/html/rfc2474#section-3
    IP_DSCP_MATCH = 46
    ETH_TYPE = 2048

    SRC_MAC = '0e:00:00:00:00:ff'
    DST_MAC = '0e:00:00:00:00:02'

    REWRITE_MAC = '0f:00:12:23:48:03'

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            ip_dscp: %d
            dl_type: 0x800
            actions:
                allow: 1
                output:
                    set_fields:
                        - eth_dst: "%s"
        - rule:
            actions:
                allow: 1
""" % (IP_DSCP_MATCH, REWRITE_MAC)
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
    """

    def test_untagged(self):
        # Tests that a packet with an ip_dscp field will be appropriately
        # matched and proceeds through the faucet pipeline. This test verifies
        # that packets with the dscp field can have their eth_dst field modified
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.REWRITE_MAC)
        self.wait_until_matching_flow(
            {'ip_dscp': self.IP_DSCP_MATCH,
             'eth_type': self.ETH_TYPE},
            table_id=self._PORT_ACL_TABLE)

        # scapy command to create and send a packet with the specified fields
        scapy_pkt = self.scapy_dscp(self.SRC_MAC, self.DST_MAC, 184,
                                    source_host.defaultIntf())

        tcpdump_filter = f"ether dst {self.REWRITE_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)
        # verify that the packet we've received on the dest_host is from the
        # source MAC address
        self.assertTrue(re.search("%s > %s" % (self.SRC_MAC, self.REWRITE_MAC),
                                  tcpdump_txt))


class FaucetOrderedDscpMatchTest(FaucetUntaggedTest):
    # Match all packets with this IP_DSP and eth_type, based on the ryu API def
    # e.g {"ip_dscp": 3, "eth_type": 2048}
    # Note: the ip_dscp field is translated to nw_tos in OpenFlow 1.0:
    # see https://tools.ietf.org/html/rfc2474#section-3
    IP_DSCP_MATCH = 46
    ETH_TYPE = 2048

    SRC_MAC = '0e:00:00:00:00:ff'
    DST_MAC = '0e:00:00:00:00:02'

    REWRITE_MAC = '0f:00:12:23:48:03'

    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"

acls:
    1:
        - rule:
            ip_dscp: %d
            dl_type: 0x800
            actions:
                allow: 1
                output:
                    - set_fields:
                        - eth_dst: "%s"
        - rule:
            actions:
                allow: 1
""" % (IP_DSCP_MATCH, REWRITE_MAC)
    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                acl_in: 1
            %(port_2)d:
                native_vlan: 100
            %(port_3)d:
                native_vlan: 100
            %(port_4)d:
                native_vlan: 100
    """

    def test_untagged(self):
        # Tests that a packet with an ip_dscp field will be appropriately
        # matched and proceeds through the faucet pipeline. This test verifies
        # that packets with the dscp field can have their eth_dst field modified
        source_host, dest_host = self.hosts_name_ordered()[0:2]
        dest_host.setMAC(self.REWRITE_MAC)
        self.wait_until_matching_flow(
            {'ip_dscp': self.IP_DSCP_MATCH,
             'eth_type': self.ETH_TYPE},
            table_id=self._PORT_ACL_TABLE)

        # scapy command to create and send a packet with the specified fields
        scapy_pkt = self.scapy_dscp(self.SRC_MAC, self.DST_MAC, 184,
                                    source_host.defaultIntf())

        tcpdump_filter = f"ether dst {self.REWRITE_MAC}"
        tcpdump_txt = self.tcpdump_helper(
            dest_host, tcpdump_filter, [lambda: source_host.cmd(scapy_pkt)],
            root_intf=True, packets=1)
        # verify that the packet we've received on the dest_host is from the
        # source MAC address
        self.assertTrue(re.search("%s > %s" % (self.SRC_MAC, self.REWRITE_MAC),
                                  tcpdump_txt))


@unittest.skip('use_idle_timeout unreliable')
class FaucetWithUseIdleTimeoutTest(FaucetUntaggedTest):
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""
    CONFIG = """
        timeout: 1
        use_idle_timeout: True
""" + CONFIG_BOILER_UNTAGGED

    def wait_for_host_removed(self, host, in_port, timeout=5):
        for _ in range(timeout):
            if not self.host_learned(host, in_port=in_port, timeout=1):
                return
        self.fail(f'host {host} still learned')

    def wait_for_flowremoved_msg(self, src_mac=None, dst_mac=None, timeout=30):
        pattern = "OFPFlowRemoved"
        mac = None
        if src_mac:
            pattern = f"OFPFlowRemoved(.*)'eth_src': '{src_mac}'"
            mac = src_mac
        if dst_mac:
            pattern = f"OFPFlowRemoved(.*)'eth_dst': '{dst_mac}'"
            mac = dst_mac
        for _ in range(timeout):
            for _, debug_log_name in self._get_ofchannel_logs():
                with open(debug_log_name, encoding='utf-8') as debug_log:
                    debug = debug_log.read()
                if re.search(pattern, debug):
                    return
            time.sleep(1)
        self.fail(f'Not received OFPFlowRemoved for host {mac}')

    def wait_for_host_log_msg(self, host_mac, msg):
        host_log_re = r'.*%s %s.*' % (msg, host_mac)
        self.wait_until_matching_lines_from_faucet_log_files(host_log_re)

    def test_untagged(self):
        self.ping_all_when_learned()
        first_host, second_host = self.hosts_name_ordered()[:2]
        self.swap_host_macs(first_host, second_host)
        for host, port in (
                (first_host, self.port_map['port_1']),
                (second_host, self.port_map['port_2'])):
            self.wait_for_flowremoved_msg(src_mac=host.MAC())
            self.require_host_learned(host, in_port=int(port))


@unittest.skip('use_idle_timeout unreliable')
class FaucetWithUseIdleTimeoutRuleExpiredTest(FaucetWithUseIdleTimeoutTest):

    def test_untagged(self):
        """Host that is actively sending should have its dst rule renewed as the
        rule expires. Host that is not sending expires as usual.
        """
        self.ping_all_when_learned()
        first_host, second_host, third_host, fourth_host = self.hosts_name_ordered()
        self.host_ipv4_alias(first_host, ipaddress.ip_interface('10.99.99.1/24'))
        first_host.cmd(f'arp -s {second_host.IP()} {second_host.MAC()}')
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


class FaucetDisconnectTest(FaucetUntaggedTest):
    """Test that switch works properly after repeated disconnections
       caused by DPID mismatch"""

    def update_config(self, dpid):
        """Update config with good/bad DPID"""
        conf = self._get_faucet_conf()
        conf['dps'][self.DP_NAME]['dp_id'] = int(dpid)
        self.reload_conf(
            conf, self.faucet_config_path,
            restart=True, cold_start=False, change_expected=False)

    def test_untagged(self):
        """Run untagged test after disconnects and config update"""
        # We update the config with a bad DPID and then wait for
        # 'unknown datapath' messages, indicating switch connections that
        # FAUCET has rejected. The switch should see them as
        # 'connection reset by peer'.
        mask = int(16 * 'f', 16)
        bad_dpid = (int(self.dpid) + 0xdeadbeef) & mask
        self.update_config(dpid=bad_dpid)
        self.wait_until_matching_lines_from_faucet_log_files(
            r'.*ERROR.*unknown datapath', timeout=60, count=4)
        self.update_config(dpid=self.dpid)
        super().test_untagged()


class FaucetBadFlowModTest(FaucetUntaggedTest):
    """Test that switch and FAUCET still work after we send some bad flow_mods"""

    def base_flow_mod(self):
        """Return a base flow mod that we mess with"""
        return {'dpid': self.dpid,
                'cookie': 0,
                'cookie_mask': 0,
                'table_id': 0,
                'idle_timeout': 29,
                'hard_timeout': 91,
                'flags': 1,
                'priority': 1,
                'match': {'in_port': 1},
                'actions': [{
                    'type': 'OUTPUT',
                    'port': 2}]}

    # For now, the flow_mods are reasonably well-formed but with
    # parameters that are incorrect for the switch and for FAUCET

    def bad_dpid(self):
        """Return a random, bad dpid parameter"""
        mask = int(16 * 'f', 16)
        dpid = (int(self.dpid) + random.randint(0, 1 << 63)) & mask
        return {'dpid': dpid}

    @staticmethod
    def bad_table():
        """Return a bad table ID parameter"""
        # This should be higher than FAUCET's max table ID
        bad_table_start = 32
        return {'table_id': random.randint(bad_table_start, 100)}

    def bad_port(self):
        """Return a (hopefully very) bad port number"""
        max_port = max(self.port_map.values())
        offset = random.randint(0x1000, 0xE0000000)
        mask = 0xEFFFFFFF
        return (max_port + offset) & mask

    def bad_match(self):
        """Return a bad match field"""
        matches = (
            # Bad input port
            {'in_port': self.bad_port()},
            # IPv4 (broadcast) src with bad ('reserved') ethertype
            {'nw_src': '255.255.255.255', 'dl_type': 0xFFFF},
            # IPv4 with IPv6 ethertype:
            {'nw_src': '1.2.3.4', 'dl_type': 0x86DD},
            # IPv4 address as IPv6 dst
            {'ipv6_dst': '1.2.3.4', 'dl_type': 0x86DD},
            # IPv6 dst with Bad/reserved ip_proto
            {'ipv6_dst': '2001::aaaa:bbbb:cccc:1111', 'ip_proto': 255},
            # Destination port but no transport protocol
            {'tp_dst': 80},
            # ARP opcode on non-ARP packetx
            {'arp_op': 0x3, 'dl_type': 0x1234})
        match = random.sample(matches, 1)[0]
        return {'match': match}

    def bad_actions(self, count=1):
        """Return a questionable actions parameter"""
        actions = (
            {'type': 'OUTPUT', 'port': self.bad_port()},
            {'type': 'PUSH_MPLS', 'ethertype': 0x8BAD},
            {'type': 'SET_QUEUE', 'queue_id':
             random.randint(0x8000, 0xFFFFFFFF)})
        return {'actions': random.sample(actions, count)}

    # Possible options for bad parameters
    bad_options = ('dpid', 'table', 'match', 'actions')

    def bad_flow_mod(self):
        """Return a flow mod with some bad parameters"""
        flow_mod = self.base_flow_mod()
        # Add two or more bad options
        options = random.sample(self.bad_options,
                                random.randint(2, len(self.bad_options)))
        for option in options:
            param = getattr(self, f'bad_{option}')()
            flow_mod.update(param)
        return flow_mod

    def send_flow_mod(self, flow_mod, timeout=5):
        """Send flow_mod to switch via ofctl"""
        int_dpid = mininet_test_util.str_int_dpid(self.dpid)
        return self._ofctl_post(int_dpid, 'stats/flowentry/modify',
                                timeout=timeout, params=flow_mod)

    def tearDown(self, ignore_oferrors=True):
        """Ignore OF errors on teardown"""
        oferrors = super().tearDown(ignore_oferrors)
        oferrors = re.findall(r'type: (\w+)', oferrors)
        counter = collections.Counter(oferrors)
        error(f'Ignored OF error count: {dict(counter)}\n')
        # TODO: ensure at least one error is always generated.

    # pylint: disable=arguments-differ
    def test_untagged(self, count=10):
        """Send a bunch of bad flow mods, then verify connectivity"""
        for _ in range(count):
            flow_mod = self.bad_flow_mod()
            error('sending bad flow_mod', flow_mod, '\n')
            self.send_flow_mod(flow_mod)
        self.ping_all_when_learned()


class FaucetUntaggedMorePortsBase(FaucetUntaggedTest):
    """Base class for untagged test with more ports"""

    # pylint: disable=invalid-name
    N_UNTAGGED = 16  # Maximum number of ports to test
    EVENT_LOGGER_TIMEOUT = 180  # Timeout for event logger process

    # Config lines for additional ports
    CONFIG_EXTRA_PORT = """
            {port}:
                native_vlan: 100""" + "\n"

    def pre_start_net(self):
        """Extend config with more ports if needed"""
        self.assertTrue(self.CONFIG.endswith(CONFIG_BOILER_UNTAGGED))
        # We know how to extend the config for more ports
        base_port_count = len(re.findall('port', CONFIG_BOILER_UNTAGGED))
        ports = self.topo.dpid_ports(self.dpid)
        for port in ports[base_port_count:]:
            self.CONFIG += self.CONFIG_EXTRA_PORT.format(port=port)
        super()._init_faucet_config()

    def setUp(self):
        """Make sure N_UNTAGGED doesn't exceed hw port count"""
        if self.config and self.config.get('hw_switch', False):
            self.N_UNTAGGED = min(len(self.config['dp_ports']),
                                  self.N_UNTAGGED)
        error(f'({self.N_UNTAGGED} ports) ')
        super().setUp()


class FaucetSingleUntagged32PortTest(FaucetUntaggedMorePortsBase):
    """Untagged test with up to 32 ports"""

    # pylint: disable=invalid-name
    N_UNTAGGED = 32  # Maximum number of ports to test


@unittest.skip('slow and potentially unreliable on travis')
class FaucetSingleUntagged48PortTest(FaucetUntaggedMorePortsBase):
    """Untagged test with up to 48 ports"""

    # pylint: disable=invalid-name
    N_UNTAGGED = 48  # Maximum number of ports to test
    EVENT_LOGGER_TIMEOUT = 360  # Timeout for event logger process
