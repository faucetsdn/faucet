#!/usr/bin/env python

"""Library for test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2019 The Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import namedtuple
from functools import partial
import cProfile
import io
import ipaddress
import logging
import os
import pstats
import shutil
import socket
import tempfile
import unittest

from ryu.lib import mac
from ryu.lib.packet import (
    arp, ethernet, icmp, icmpv6, ipv4, ipv6, lldp, slow, packet, vlan)
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser
from prometheus_client import CollectorRegistry
from beka.route import RouteAddition, RouteRemoval
from beka.ip import IPAddress, IPPrefix

from faucet import faucet_bgp
from faucet import faucet_dot1x
from faucet import faucet_event
from faucet import faucet_metrics
from faucet import valves_manager
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_util
from faucet.valve import TfmValve

from fakeoftable import FakeOFTable


def build_pkt(pkt):
    """Build and return a packet and eth type from a dict."""

    def serialize(layers):
        """Concatenate packet layers and serialize."""
        result = packet.Packet()
        for layer in reversed(layers):
            result.add_protocol(layer)
        result.serialize()
        return result

    layers = []
    assert 'eth_dst' in pkt and 'eth_src' in pkt
    ethertype = None
    if 'arp_source_ip' in pkt and 'arp_target_ip' in pkt:
        ethertype = ether.ETH_TYPE_ARP
        arp_code = pkt.get('arp_code', arp.ARP_REQUEST)
        layers.append(arp.arp(
            src_ip=pkt['arp_source_ip'],
            dst_ip=pkt['arp_target_ip'],
            opcode=arp_code))
    elif 'ipv6_src' in pkt and 'ipv6_dst' in pkt:
        ethertype = ether.ETH_TYPE_IPV6
        if 'router_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_ROUTER_SOLICIT))
        elif 'neighbor_advert_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_ADVERT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_advert_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'neighbor_solicit_ip' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ND_NEIGHBOR_SOLICIT,
                data=icmpv6.nd_neighbor(
                    dst=pkt['neighbor_solicit_ip'],
                    option=icmpv6.nd_option_sla(hw_src=pkt['eth_src']))))
        elif 'echo_request_data' in pkt:
            layers.append(icmpv6.icmpv6(
                type_=icmpv6.ICMPV6_ECHO_REQUEST,
                data=icmpv6.echo(id_=1, seq=1, data=pkt['echo_request_data'])))
        layers.append(ipv6.ipv6(
            src=pkt['ipv6_src'],
            dst=pkt['ipv6_dst'],
            nxt=inet.IPPROTO_ICMPV6))
    elif 'ipv4_src' in pkt and 'ipv4_dst' in pkt:
        ethertype = ether.ETH_TYPE_IP
        proto = inet.IPPROTO_IP
        if 'echo_request_data' in pkt:
            echo = icmp.echo(id_=1, seq=1, data=pkt['echo_request_data'])
            layers.append(icmp.icmp(type_=icmp.ICMP_ECHO_REQUEST, data=echo))
            proto = inet.IPPROTO_ICMP
        net = ipv4.ipv4(src=pkt['ipv4_src'], dst=pkt['ipv4_dst'], proto=proto)
        layers.append(net)
    elif 'actor_system' in pkt and 'partner_system' in pkt:
        ethertype = ether.ETH_TYPE_SLOW
        layers.append(slow.lacp(
            version=1,
            actor_system=pkt['actor_system'],
            actor_port=1,
            partner_system=pkt['partner_system'],
            partner_port=1,
            actor_key=1,
            partner_key=1,
            actor_system_priority=65535,
            partner_system_priority=1,
            actor_port_priority=255,
            partner_port_priority=255,
            actor_state_defaulted=0,
            partner_state_defaulted=0,
            actor_state_expired=0,
            partner_state_expired=0,
            actor_state_timeout=1,
            partner_state_timeout=1,
            actor_state_collecting=1,
            partner_state_collecting=1,
            actor_state_distributing=1,
            partner_state_distributing=1,
            actor_state_aggregation=1,
            partner_state_aggregation=1,
            actor_state_synchronization=pkt['actor_state_synchronization'],
            partner_state_synchronization=1,
            actor_state_activity=0,
            partner_state_activity=0))
    elif 'chassis_id' in pkt and 'port_id' in pkt:
        ethertype = ether.ETH_TYPE_LLDP
        return valve_packet.lldp_beacon(
            pkt['eth_src'], pkt['chassis_id'], str(pkt['port_id']), 1,
            org_tlvs=pkt.get('org_tlvs', None),
            system_name=pkt.get('system_name', None))
    assert ethertype is not None, pkt
    if 'vid' in pkt:
        tpid = ether.ETH_TYPE_8021Q
        layers.append(vlan.vlan(vid=pkt['vid'], ethertype=ethertype))
    else:
        tpid = ethertype
    eth = ethernet.ethernet(
        dst=pkt['eth_dst'],
        src=pkt['eth_src'],
        ethertype=tpid)
    layers.append(eth)
    result = serialize(layers)
    return result


FAUCET_MAC = '0e:00:00:00:00:01'

BASE_DP_CONFIG = """
        hardware: 'GenericTFM'
        ignore_learn_ins: 100
        ofchannel_log: '/dev/null'
        packetin_pps: 99
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
"""

BASE_DP1_CONFIG = """
        dp_id: 1
""" + BASE_DP_CONFIG

DP1_CONFIG = """
        combinatorial_port_flood: True
""" + BASE_DP1_CONFIG

IDLE_DP1_CONFIG = """
        use_idle_timeout: True
""" + DP1_CONFIG

GROUP_DP1_CONFIG = """
        group_table: True
""" + BASE_DP1_CONFIG

DOT1X_CONFIG = """
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: 127.0.0.1
            radius_port: 1234
            radius_secret: SECRET
""" + BASE_DP1_CONFIG

DOT1X_ACL_CONFIG = """
        dot1x:
            nfv_intf: lo
            nfv_sw_port: 2
            radius_ip: 127.0.0.1
            radius_port: 1234
            radius_secret: SECRET
            auth_acl: auth_acl
            noauth_acl: noauth_acl
""" + BASE_DP1_CONFIG

CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                loop_protect: True
                receive_lldp: True
                max_hosts: 1
                hairpin: True
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
                loop_protect: True
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]

    s2:
        hardware: 'GenericTFM'
        dp_id: 0xdeadbeef
        interfaces:
            p1:
                number: 1
                native_vlan: v100
    s3:
        hardware: 'GenericTFM'
        combinatorial_port_flood: True
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                stack:
                    dp: s4
                    port: 5
    s4:
        hardware: 'GenericTFM'
        dp_id: 0x4
        interfaces:
            p1:
                number: 1
                native_vlan: v300
            p2:
                number: 2
                native_vlan: v300
            p3:
                number: 3
                native_vlan: v300
            p4:
                number: 4
                native_vlan: v300
            5:
                description: p5
                number: 5
                stack:
                    dp: s3
                    port: 5
routers:
    router1:
        vlans: [v100, v200]
vlans:
    v100:
        vid: 0x100
        targeted_gw_resolution: True
        faucet_vips: ['10.0.0.254/24']
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
            - route:
                ip_dst: 10.99.98.0/24
                ip_gw: 10.0.0.99
    v200:
        vid: 0x200
        faucet_vips: ['fc00::1:254/112', 'fe80::1:254/64']
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
    v300:
        vid: 0x300
    v400:
        vid: 0x400
""" % DP1_CONFIG


STACK_CONFIG = """
dps:
    s1:
%s
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 1
            2:
                description: p2
                stack:
                    dp: s2
                    port: 2
            3:
                description: p3
                native_vlan: v100
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        stack:
            priority: 2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                stack:
                    dp: s1
                    port: 2
            3:
                description: p3
                stack:
                    dp: s3
                    port: 2
            4:
                description: p4
                native_vlan: v100
    s3:
        dp_id: 0x3
        hardware: 'GenericTFM'
        interfaces:
            1:
                description: p1
                native_vlan: v100
            2:
                description: p2
                stack:
                    dp: s2
                    port: 3
vlans:
    v100:
        vid: 100
    """ % DP1_CONFIG

STACK_LOOP_CONFIG = """
dps:
    s1:
%s
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 1
            2:
                description: p2
                stack:
                    dp: s3
                    port: 1
            3:
                description: p3
                native_vlan: 100
    s2:
%s
        faucet_dp_mac: 0e:00:00:00:01:02
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                stack:
                    dp: s3
                    port: 2
            3:
                description: p3
                native_vlan: 100
    s3:
%s
        faucet_dp_mac: 0e:00:00:00:01:03
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 2
            2:
                description: p2
                stack:
                    dp: s2
                    port: 2
            3:
                description: p3
                native_vlan: 100
vlans:
    v100:
        vid: 100
""" % (BASE_DP1_CONFIG, BASE_DP_CONFIG, BASE_DP_CONFIG)


class ValveTestBases:
    """Insulate test base classes from unittest so we can reuse base clases."""

    class ValveTestSmall(unittest.TestCase):  # pytype: disable=module-attr
        """Base class for all Valve unit tests."""

        DP = 's1'
        DP_ID = 1
        NUM_PORTS = 5
        NUM_TABLES = 10
        P1_V100_MAC = '00:00:00:01:00:01'
        P2_V200_MAC = '00:00:00:02:00:02'
        P3_V200_MAC = '00:00:00:02:00:03'
        P1_V300_MAC = '00:00:00:03:00:01'
        UNKNOWN_MAC = '00:00:00:04:00:04'
        V100 = 0x100 | ofp.OFPVID_PRESENT
        V200 = 0x200 | ofp.OFPVID_PRESENT
        V300 = 0x300 | ofp.OFPVID_PRESENT
        LOGNAME = 'faucet'
        ICMP_PAYLOAD = bytes('A'*64, encoding='UTF-8')  # must support 64b payload.
        REQUIRE_TFM = True
        CONFIG_AUTO_REVERT = False

        def __init__(self, *args, **kwargs):
            self.dot1x = None
            self.last_flows_to_dp = {}
            self.valve = None
            self.valves_manager = None
            self.metrics = None
            self.bgp = None
            self.table = None
            self.logger = None
            self.tmpdir = None
            self.faucet_event_sock = None
            self.registry = None
            self.sock = None
            self.notifier = None
            self.config_file = None
            self.up_ports = {}
            self.mock_now_sec = 100
            super(ValveTestBases.ValveTestSmall, self).__init__(*args, **kwargs)

        def mock_time(self, increment_sec=1):
            """Manage a mock timer for better unit test control"""
            self.mock_now_sec += increment_sec
            return self.mock_now_sec

        def setup_valve(self, config, error_expected=0):
            """Set up test DP with config."""
            self.tmpdir = tempfile.mkdtemp()
            self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
            self.faucet_event_sock = os.path.join(self.tmpdir, 'event.sock')
            self.table = FakeOFTable(self.NUM_TABLES)
            logfile = os.path.join(self.tmpdir, 'faucet.log')
            self.logger = valve_util.get_logger(self.LOGNAME, logfile, logging.DEBUG, 0)
            self.registry = CollectorRegistry()
            self.metrics = faucet_metrics.FaucetMetrics(reg=self.registry)  # pylint: disable=unexpected-keyword-arg
            # TODO: verify events
            self.notifier = faucet_event.FaucetEventNotifier(
                self.faucet_event_sock, self.metrics, self.logger)
            self.bgp = faucet_bgp.FaucetBgp(
                self.logger, logfile, self.metrics, self.send_flows_to_dp_by_id)
            self.dot1x = faucet_dot1x.FaucetDot1x(
                self.logger, logfile, self.metrics, self.send_flows_to_dp_by_id)
            self.valves_manager = valves_manager.ValvesManager(
                self.LOGNAME, self.logger, self.metrics, self.notifier,
                self.bgp, self.dot1x, self.CONFIG_AUTO_REVERT, self.send_flows_to_dp_by_id)
            self.last_flows_to_dp[self.DP_ID] = []
            self.notifier.start()
            initial_ofmsgs = self.update_config(config, reload_expected=False, error_expected=error_expected)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.faucet_event_sock)
            if not error_expected:
                self.connect_dp()
            return initial_ofmsgs

        def teardown_valve(self):
            """Tear down test DP."""
            self.bgp.shutdown_bgp_speakers()
            valve_util.close_logger(self.logger)
            for valve in list(self.valves_manager.valves.values()):
                valve.close_logs()
            self.sock.close()
            shutil.rmtree(self.tmpdir)

        def tearDown(self):
            self.teardown_valve()

        def apply_ofmsgs(self, ofmsgs):
            """Postprocess flows before sending to simulated DP."""
            final_ofmsgs = self.valve.prepare_send_flows(ofmsgs)
            self.table.apply_ofmsgs(final_ofmsgs)
            return final_ofmsgs

        @staticmethod
        def profile(func, sortby='cumulative', amount=20, count=1):
            """Convenience method to profile a function call."""
            prof = cProfile.Profile()
            prof.enable()
            for _ in range(count):
                func()
            prof.disable()
            prof_stream = io.StringIO()
            prof_stats = pstats.Stats(prof, stream=prof_stream).sort_stats(sortby)
            prof_stats.print_stats(amount)
            return (prof_stats, prof_stream.getvalue())

        def get_prom(self, var, labels=None, bare=False):
            """Return a Prometheus variable value."""
            if labels is None:
                labels = {}
            if not bare:
                labels.update({
                    'dp_name': self.DP,
                    'dp_id': '0x%x' % self.DP_ID})
            val = self.registry.get_sample_value(var, labels)
            if val is None:
                val = 0
            return val

        def prom_inc(self, func, var, labels=None, inc_expected=True):
            """Check Prometheus variable increments by 1 after calling a function."""
            before = self.get_prom(var, labels)
            func()
            after = self.get_prom(var, labels)
            msg = '%s %s before %f after %f' % (var, labels, before, after)
            if inc_expected:
                self.assertEqual(before + 1, after, msg=msg)
            else:
                self.assertEqual(before, after, msg=msg)

        def send_flows_to_dp_by_id(self, valve, flows):
            """Callback for ValvesManager to simulate sending flows to DP."""
            flows = valve.prepare_send_flows(flows)
            self.last_flows_to_dp[valve.dp.dp_id] = flows

        def update_config(self, config, reload_type='cold',
                          reload_expected=True, error_expected=0):
            """Update FAUCET config with config as text."""
            before_dp_status = int(self.get_prom('dp_status'))
            existing_config = None
            if os.path.exists(self.config_file):
                with open(self.config_file) as config_file:
                    existing_config = config_file.read()
            with open(self.config_file, 'w') as config_file:
                config_file.write(config)
            content_change_expected = config != existing_config
            self.assertEqual(
                content_change_expected,
                self.valves_manager.config_watcher.content_changed(self.config_file))
            self.last_flows_to_dp[self.DP_ID] = []
            reload_ofmsgs = []
            reload_func = partial(
                self.valves_manager.request_reload_configs,
                self.mock_time(10), self.config_file)

            if error_expected:
                reload_func()
            else:
                var = 'faucet_config_reload_%s_total' % reload_type
                self.prom_inc(reload_func, var=var, inc_expected=reload_expected)
                self.valve = self.valves_manager.valves[self.DP_ID]
                if self.DP_ID in self.last_flows_to_dp:
                    reload_ofmsgs = self.last_flows_to_dp[self.DP_ID]
                    # DP requested reconnection
                    if reload_ofmsgs is None:
                        reload_ofmsgs = self.connect_dp()
                    else:
                        self.apply_ofmsgs(reload_ofmsgs)
            self.assertEqual(before_dp_status, int(self.get_prom('dp_status')))
            self.assertEqual(error_expected, self.get_prom('faucet_config_load_error', bare=True))
            return reload_ofmsgs

        def connect_dp(self):
            """Call DP connect and wth all ports up."""
            discovered_up_ports = set(list(self.valve.dp.ports.keys())[:self.NUM_PORTS])
            connect_msgs = (
                self.valve.switch_features(None) +
                self.valve.datapath_connect(self.mock_time(10), discovered_up_ports))
            self.apply_ofmsgs(connect_msgs)
            self.valves_manager.update_config_applied(sent={self.DP_ID: True})
            self.assertEqual(1, int(self.get_prom('dp_status')))
            self.assertTrue(self.valve.dp.to_conf())
            return connect_msgs

        def port_labels(self, port_no):
            """Get port labels"""
            port = self.valve.dp.ports[port_no]
            return {'port': port.name, 'port_description': port.description}

        def port_expected_status(self, port_no, exp_status):
            """Verify port has status"""
            if port_no not in self.valve.dp.ports:
                return
            labels = self.port_labels(port_no)
            status = int(self.get_prom('port_status', labels=labels))
            self.assertEqual(
                status, exp_status,
                msg='status %u != expected %u for port %s' % (
                    status, exp_status, labels))

        def set_port_down(self, port_no):
            """Set port status of port to down."""
            self.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_DELETE, ofp.OFPPS_LINK_DOWN, []).get(self.valve, []))
            self.port_expected_status(port_no, 0)

        def set_port_up(self, port_no):
            """Set port status of port to up."""
            self.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_ADD, 0, []).get(self.valve, []))
            self.port_expected_status(port_no, 1)

        def flap_port(self, port_no):
            """Flap op status on a port."""
            self.set_port_down(port_no)
            self.set_port_up(port_no)

        def all_stack_up(self):
            """Bring all the ports in a stack fully up"""
            for valve in self.valves_manager.valves.values():
                valve.dp.dyn_running = True
                for port in valve.dp.stack_ports:
                    port.stack_up()

        def up_stack_port(self, port, dp_id=None):
            """Bring up a single stack port"""
            peer_dp = port.stack['dp']
            peer_port = port.stack['port']
            for state_func in [peer_port.stack_init, peer_port.stack_up]:
                state_func()
                self.rcv_lldp(port, peer_dp, peer_port, dp_id)
            self.assertTrue(port.is_stack_up())

        def down_stack_port(self, port):
            """Bring down a single stack port"""
            self.up_stack_port(port)
            peer_port = port.stack['port']
            peer_port.stack_gone()
            now = self.mock_time(600)
            self.valves_manager.valve_flow_services(
                now,
                'fast_state_expire')
            self.assertTrue(port.is_stack_gone())

        def _update_port_map(self, port, add_else_remove):
            this_dp = port.dp_id
            this_num = port.number
            this_key = '%s:%s' % (this_dp, this_num)
            peer_dp = port.stack['dp'].dp_id
            peer_num = port.stack['port'].number
            peer_key = '%s:%s' % (peer_dp, peer_num)
            key_array = [this_key, peer_key]
            key_array.sort()
            key = key_array[0]
            if add_else_remove:
                self.up_ports[key] = port
            else:
                del self.up_ports[key]

        def activate_all_ports(self, packets=10):
            """Activate all stack ports through LLDP"""
            for valve in self.valves_manager.valves.values():
                valve.dp.dyn_running = True
                for port in valve.dp.stack_ports:
                    self.up_stack_port(port, dp_id=valve.dp.dp_id)
                    self._update_port_map(port, True)
            self.trigger_all_ports(packets=packets)

        def trigger_all_ports(self, packets=10):
            """Do the needful to trigger any pending state changes"""
            interval = self.valve.dp.lldp_beacon['send_interval']
            for _ in range(0, packets):
                for port in self.up_ports.values():
                    dp_id = port.dp_id
                    this_dp = self.valves_manager.valves[dp_id].dp
                    peer_dp = port.stack['dp']
                    peer_port = port.stack['port']
                    self.rcv_lldp(port, peer_dp, peer_port, dp_id)
                    self.rcv_lldp(peer_port, this_dp, port, peer_dp.dp_id)
                self.last_flows_to_dp[self.DP_ID] = []
                now = self.mock_time(interval)
                self.valves_manager.valve_flow_services(
                    now, 'fast_state_expire')
                flows = self.last_flows_to_dp[self.DP_ID]
                self.apply_ofmsgs(flows)

        def deactivate_stack_port(self, port, packets=10):
            """Deactivate a given stack port"""
            self._update_port_map(port, False)
            self.trigger_all_ports(packets=packets)

        def activate_stack_port(self, port, packets=10):
            """Deactivate a given stack port"""
            self._update_port_map(port, True)
            self.trigger_all_ports(packets=packets)

        @staticmethod
        def packet_outs_from_flows(flows):
            """Return flows that are packetout actions."""
            return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPPacketOut)]

        @staticmethod
        def flowmods_from_flows(flows):
            """Return flows that are flowmods actions."""
            return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPFlowMod)]

        def learn_hosts(self):
            """Learn some hosts."""
            # TODO: verify learn caching.
            for _ in range(2):
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.2'})
                # TODO: verify host learning banned
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.UNKNOWN_MAC,
                    'eth_dst': self.P1_V100_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.1'})
                self.rcv_packet(2, 0x200, {
                    'eth_src': self.P2_V200_MAC,
                    'eth_dst': self.P3_V200_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.3',
                    'vid': 0x200})
                self.rcv_packet(3, 0x200, {
                    'eth_src': self.P3_V200_MAC,
                    'eth_dst': self.P2_V200_MAC,
                    'ipv4_src': '10.0.0.3',
                    'ipv4_dst': '10.0.0.4',
                    'vid': 0x200})

        def verify_expiry(self):
            """Verify FIB resolution attempts expire."""
            for _ in range(self.valve.dp.max_host_fib_retry_count + 1):
                now = self.mock_time(self.valve.dp.timeout * 2)
                self.valve.state_expire(now, None)
                self.valve.resolve_gateways(now, None)
            # TODO: verify state expired

        def verify_flooding(self, matches):
            """Verify flooding for a packet, depending on the DP implementation."""

            def _verify_flood_to_port(match, port, valve_vlan, port_number=None):
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid | ofp.OFPVID_PRESENT
                else:
                    vid = 0
                if port_number is None:
                    port_number = port.number
                return self.table.is_output(match, port=port_number, vid=vid)

            for match in matches:
                in_port_number = match['in_port']
                in_port = self.valve.dp.ports[in_port_number]

                if ('vlan_vid' in match and
                        match['vlan_vid'] & ofp.OFPVID_PRESENT != 0):
                    valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
                else:
                    valve_vlan = in_port.native_vlan

                all_ports = {
                    port for port in self.valve.dp.ports.values() if port.running()}
                remaining_ports = all_ports - {
                    port for port in valve_vlan.get_ports() if port.running}

                hairpin_output = _verify_flood_to_port(
                    match, in_port, valve_vlan, ofp.OFPP_IN_PORT)
                self.assertEqual(
                    in_port.hairpin, hairpin_output,
                    msg='hairpin flooding incorrect (expected %s got %s)' % (
                        in_port.hairpin, hairpin_output))

                for port in valve_vlan.get_ports():
                    output = _verify_flood_to_port(match, port, valve_vlan)
                    if self.valve.floods_to_root():
                        # Packet should only be flooded to root.
                        self.assertEqual(False, output, 'unexpected non-root flood')
                    else:
                        # Packet must be flooded to all ports on the VLAN.
                        if port == in_port:
                            self.assertEqual(port.hairpin, output,
                                             'unexpected hairpin flood %s %u' % (
                                                 match, port.number))
                        else:
                            self.assertTrue(
                                output,
                                msg=('%s with unknown eth_dst not flooded'
                                     ' on VLAN %u to port %u\n%s' % (
                                         match, valve_vlan.vid, port.number, self.table)))

                # Packet must not be flooded to ports not on the VLAN.
                for port in remaining_ports:
                    if port.stack:
                        self.assertTrue(
                            self.table.is_output(match, port=port.number),
                            msg=('Unknown eth_dst not flooded to stack port %s' % port))
                    elif not port.mirror:
                        self.assertFalse(
                            self.table.is_output(match, port=port.number),
                            msg=('Unknown eth_dst flooded to non-VLAN/stack/mirror %s' % port))

        def rcv_packet(self, port, vid, match):
            """Simulate control plane receiving a packet on a port/VID."""
            pkt = build_pkt(match)
            vlan_pkt = pkt
            # TODO: VLAN packet submitted to packet in always has VID
            # Fake OF switch implementation should do this by applying actions.
            if vid and vid not in match:
                vlan_match = match
                vlan_match['vid'] = vid
                vlan_pkt = build_pkt(match)
            msg = namedtuple(
                'null_msg',
                ('match', 'in_port', 'data', 'total_len', 'cookie', 'reason'))(
                    {'in_port': port}, port, vlan_pkt.data, len(vlan_pkt.data),
                    self.valve.dp.cookie, valve_of.ofp.OFPR_ACTION)
            self.last_flows_to_dp[self.DP_ID] = []
            now = self.mock_time(0)
            self.prom_inc(
                partial(self.valves_manager.valve_packet_in, now, self.valve, msg),
                'of_packet_ins_total')
            rcv_packet_ofmsgs = self.last_flows_to_dp[self.DP_ID]
            self.apply_ofmsgs(rcv_packet_ofmsgs)
            for valve_service in (
                    'resolve_gateways', 'advertise', 'fast_advertise', 'state_expire'):
                self.valves_manager.valve_flow_services(
                    now, valve_service)
            self.valves_manager.update_metrics(now)
            return rcv_packet_ofmsgs

        def rcv_lldp(self, port, other_dp, other_port, dp_id=None):
            """Receive an LLDP packet"""
            dp_id = dp_id if dp_id else self.DP_ID
            tlvs = []
            tlvs.extend(valve_packet.faucet_lldp_tlvs(other_dp))
            tlvs.extend(valve_packet.faucet_lldp_stack_state_tlvs(other_dp, other_port))
            dp_mac = other_dp.faucet_dp_mac if other_dp.faucet_dp_mac else FAUCET_MAC
            flows = self.valve_rcv_packet(port.number, 0, {
                'eth_src': dp_mac,
                'eth_dst': lldp.LLDP_MAC_NEAREST_BRIDGE,
                'port_id': other_port.number,
                'chassis_id': dp_mac,
                'system_name': other_dp.name,
                'org_tlvs': tlvs}, dp_id)
            if dp_id == self.DP_ID:
                self.apply_ofmsgs(flows)

        def valve_rcv_packet(self, port, vid, match, dp_id):
            """Simulate control plane receiving a packet on a port/VID."""
            valve = self.valves_manager.valves[dp_id]
            pkt = build_pkt(match)
            vlan_pkt = pkt
            if vid and vid not in match:
                vlan_match = match
                vlan_match['vid'] = vid
                vlan_pkt = build_pkt(match)
            msg = namedtuple(
                'null_msg',
                ('match', 'in_port', 'data', 'total_len', 'cookie', 'reason'))(
                    {'in_port': port}, port, vlan_pkt.data, len(vlan_pkt.data),
                    valve.dp.cookie, valve_of.ofp.OFPR_ACTION)
            self.last_flows_to_dp[dp_id] = []
            now = self.mock_time(0)
            self.valves_manager.valve_packet_in(now, valve, msg)
            for valve_service in (
                    'resolve_gateways', 'advertise', 'fast_advertise', 'state_expire'):
                self.valves_manager.valve_flow_services(
                    now, valve_service)
            self.valves_manager.update_metrics(now)
            rcv_packet_ofmsgs = self.last_flows_to_dp[dp_id]
            return rcv_packet_ofmsgs

        def set_stack_port_status(self, port_no, status):
            """Set stack port up recalculating topology as necessary."""
            port = self.valve.dp.ports[port_no]
            port.dyn_stack_current_state = status
            self.valve.flood_manager.update_stack_topo(True, self.valve.dp, port)
            for valve_vlan in self.valve.dp.vlans.values():
                self.apply_ofmsgs(self.valve.flood_manager.add_vlan(valve_vlan))

        def set_stack_port_up(self, port_no):
            """Set stack port up recalculating topology as necessary."""
            self.set_stack_port_status(port_no, 3)

        def set_stack_port_down(self, port_no):
            """Set stack port up recalculating topology as necessary."""
            self.set_stack_port_status(port_no, 2)

    class ValveTestBig(ValveTestSmall):
        """Test basic switching/L2/L3 functions."""

        def setUp(self):
            self.setup_valve(CONFIG)

        def test_notifier_socket_path(self):
            """Test notifier socket path checker."""
            new_path = os.path.join(self.tmpdir, 'new_path/new_socket')
            self.assertEqual(self.notifier.check_path(new_path), new_path)
            stale_socket = os.path.join(self.tmpdir, 'stale_socket')
            with open(stale_socket, 'w') as stale_socket_file:
                stale_socket_file.write('')
            self.assertEqual(self.notifier.check_path(stale_socket), stale_socket)

        def test_disconnect(self):
            """Test disconnection of DP from controller."""
            self.assertEqual(1, int(self.get_prom('dp_status')))
            self.prom_inc(partial(self.valve.datapath_disconnect), 'of_dp_disconnections_total')
            self.assertEqual(0, int(self.get_prom('dp_status')))

        def test_unexpected_port(self):
            """Test packet in from unexpected port."""
            self.prom_inc(
                partial(self.rcv_packet, 999, 0x100, {
                    'eth_src': self.P1_V300_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.2'}),
                'of_unexpected_packet_ins_total',
                inc_expected=True)

        def test_oferror(self):
            """Test OFError handler."""
            datapath = None
            msg = valve_of.parser.OFPFlowMod(datapath=datapath)
            msg.xid = 123
            self.valve.recent_ofmsgs.append(msg)
            test_error = valve_of.parser.OFPErrorMsg(datapath=datapath, msg=msg)
            self.valve.oferror(test_error)

        def test_tfm(self):
            """Test TFM is sent."""
            self.assertTrue(
                isinstance(self.valve, TfmValve),
                msg=type(self.valve))
            discovered_up_ports = {port_no for port_no in range(1, self.NUM_PORTS + 1)}
            flows = self.valve.datapath_connect(self.mock_time(10), discovered_up_ports)
            self.apply_ofmsgs(flows)
            tfm_flows = [
                flow for flow in flows if isinstance(
                    flow, valve_of.parser.OFPTableFeaturesStatsRequest)]
            # TODO: verify TFM content.
            self.assertTrue(tfm_flows)

        def test_pkt_meta(self):
            """Test bad fields in OFPacketIn."""
            msg = parser.OFPPacketIn(datapath=None)
            self.assertEqual(None, self.valve.parse_pkt_meta(msg))
            msg.cookie = self.valve.dp.cookie
            self.assertEqual(None, self.valve.parse_pkt_meta(msg))
            msg.reason = valve_of.ofp.OFPR_ACTION
            self.assertEqual(None, self.valve.parse_pkt_meta(msg))
            msg.match = parser.OFPMatch(in_port=1)
            self.assertEqual(None, self.valve.parse_pkt_meta(msg))
            msg.data = b'1234'
            self.assertEqual(None, self.valve.parse_pkt_meta(msg))

        def test_loop_protect(self):
            """Learn loop protection."""
            for _ in range(2):
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.2'})
                self.rcv_packet(2, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.2',
                    'vid': 0x100})

        def test_lldp(self):
            """Test LLDP reception."""
            self.assertFalse(self.rcv_packet(1, 0, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': lldp.LLDP_MAC_NEAREST_BRIDGE,
                'chassis_id': self.P1_V100_MAC,
                'port_id': 1}))

        def test_bogon_arp_for_controller(self):
            """Bogon ARP request for controller VIP."""
            replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
                'arp_code': arp.ARP_REQUEST,
                'arp_source_ip': '8.8.8.8',
                'arp_target_ip': '10.0.0.254'})
            # Must be no ARP reply to an ARP request not in our subnet.
            self.assertFalse(self.packet_outs_from_flows(replies))

        def test_arp_for_controller(self):
            """ARP request for controller VIP."""
            for _retries in range(3):
                for arp_mac in (mac.BROADCAST_STR, self.valve.dp.vlans[0x100].faucet_mac):
                    arp_replies = self.rcv_packet(1, 0x100, {
                        'eth_src': self.P1_V100_MAC,
                        'eth_dst': arp_mac,
                        'arp_code': arp.ARP_REQUEST,
                        'arp_source_ip': '10.0.0.1',
                        'arp_target_ip': '10.0.0.254'})
                    # TODO: check ARP reply is valid
                    self.assertTrue(self.packet_outs_from_flows(arp_replies), msg=arp_mac)

        def test_arp_reply_from_host(self):
            """ARP reply for host."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'arp_code': arp.ARP_REPLY,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})
            # TODO: check ARP reply is valid
            self.assertTrue(arp_replies)
            self.assertFalse(self.packet_outs_from_flows(arp_replies))

        def test_nd_for_controller(self):
            """IPv6 ND for controller VIP."""
            for dst_ip in (
                    ipaddress.IPv6Address('fe80::1:254'),
                    ipaddress.IPv6Address('fc00::1:254')):
                nd_mac = valve_packet.ipv6_link_eth_mcast(dst_ip)
                ip_gw_mcast = valve_packet.ipv6_solicited_node_from_ucast(dst_ip)
                for _retries in range(3):
                    nd_replies = self.rcv_packet(2, 0x200, {
                        'eth_src': self.P2_V200_MAC,
                        'eth_dst': nd_mac,
                        'vid': 0x200,
                        'ipv6_src': 'fc00::1:1',
                        'ipv6_dst': str(ip_gw_mcast),
                        'neighbor_solicit_ip': str(dst_ip)})
                    # TODO: check reply NA is valid
                    packet_outs = self.packet_outs_from_flows(nd_replies)
                    self.assertTrue(packet_outs)

        def test_nd_from_host(self):
            """IPv6 NA from host."""
            na_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:1',
                'ipv6_dst': 'fc00::1:254',
                'neighbor_advert_ip': 'fc00::1:1'})
            # TODO: check NA response flows are valid
            self.assertTrue(na_replies)
            self.assertFalse(self.packet_outs_from_flows(na_replies))

        def test_ra_for_controller(self):
            """IPv6 RA for controller."""
            router_solicit_ip = 'ff02::2'
            ra_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': '33:33:00:00:00:02',
                'vid': 0x200,
                'ipv6_src': 'fe80::1:1',
                'ipv6_dst': router_solicit_ip,
                'router_solicit_ip': router_solicit_ip})
            # TODO: check RA is valid
            self.assertTrue(self.packet_outs_from_flows(ra_replies))

        def test_icmp_ping_controller(self):
            """IPv4 ping controller VIP."""
            echo_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.254',
                'echo_request_data': self.ICMP_PAYLOAD})
            packet_outs = self.packet_outs_from_flows(echo_replies)
            self.assertTrue(packet_outs)
            data = packet_outs[0].data
            self.assertTrue(data.endswith(self.ICMP_PAYLOAD), msg=data)

        def test_unresolved_route(self):
            """Test unresolved route tries to resolve."""
            ip_dst = ipaddress.IPv4Network('10.100.100.0/24')
            ip_gw = ipaddress.IPv4Address('10.0.0.1')
            valve_vlan = self.valve.dp.vlans[0x100]
            route_add_replies = self.valve.add_route(
                valve_vlan, ip_gw, ip_dst)
            self.assertFalse(route_add_replies)
            resolve_replies = self.valve.resolve_gateways(
                self.mock_time(10), None)
            self.assertFalse(resolve_replies)
            resolve_replies = self.valve.resolve_gateways(
                self.mock_time(99), None)
            self.assertTrue(resolve_replies)

        def test_add_del_route(self):
            """IPv4 add/del of a route."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
                'arp_code': arp.ARP_REQUEST,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})
            # TODO: check ARP reply is valid
            self.assertTrue(self.packet_outs_from_flows(arp_replies))
            valve_vlan = self.valve.dp.vlans[0x100]
            ip_dst = ipaddress.IPv4Network('10.100.100.0/24')
            ip_gw = ipaddress.IPv4Address('10.0.0.1')
            route_add_replies = self.valve.add_route(
                valve_vlan, ip_gw, ip_dst)
            # TODO: check add flows.
            self.assertTrue(route_add_replies)
            route_del_replies = self.valve.del_route(
                valve_vlan, ip_dst)
            # TODO: check del flows.
            self.assertTrue(route_del_replies)

        def test_host_ipv4_fib_route(self):
            """Test learning a FIB rule for an IPv4 host."""
            fib_route_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.2',
                'ipv4_dst': '10.0.0.4',
                'echo_request_data': bytes(
                    'A'*8, encoding='UTF-8')})  # pytype: disable=wrong-keyword-args
            # TODO: verify learning rule contents
            # We want to know this host was learned we did not get packet outs.
            self.assertTrue(fib_route_replies)
            # Verify adding default route via 10.0.0.2
            self.assertTrue((self.valve.add_route(
                self.valve.dp.vlans[0x100],
                ipaddress.IPv4Address('10.0.0.2'),
                ipaddress.IPv4Network('0.0.0.0/0'))))
            self.assertFalse(self.packet_outs_from_flows(fib_route_replies))
            self.verify_expiry()

        def test_host_ipv6_fib_route(self):
            """Test learning a FIB rule for an IPv6 host."""
            fib_route_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:2',
                'ipv6_dst': 'fc00::1:4',
                'echo_request_data': self.ICMP_PAYLOAD})
            # TODO: verify learning rule contents
            # We want to know this host was learned we did not get packet outs.
            self.assertTrue(fib_route_replies)
            self.assertFalse(self.packet_outs_from_flows(fib_route_replies))
            self.verify_expiry()

        def test_ping_unknown_neighbor(self):
            """IPv4 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.99',
                'echo_request_data': self.ICMP_PAYLOAD})
            # TODO: check proactive neighbor resolution
            self.assertTrue(self.packet_outs_from_flows(echo_replies))

        def test_ping6_unknown_neighbor(self):
            """IPv6 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:2',
                'ipv6_dst': 'fc00::1:4',
                'echo_request_data': self.ICMP_PAYLOAD})
            # TODO: check proactive neighbor resolution
            self.assertTrue(self.packet_outs_from_flows(echo_replies))

        def test_icmpv6_ping_controller(self):
            """IPv6 ping controller VIP."""
            echo_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:1',
                'ipv6_dst': 'fc00::1:254',
                'echo_request_data': self.ICMP_PAYLOAD})
            packet_outs = self.packet_outs_from_flows(echo_replies)
            self.assertTrue(packet_outs)
            data = packet_outs[0].data
            self.assertTrue(data.endswith(self.ICMP_PAYLOAD), msg=data)

        def test_invalid_vlan(self):
            """Test that packets with incorrect vlan tagging get dropped."""

            matches = [
                {'in_port': 1, 'vlan_vid': 18 | ofp.OFPVID_PRESENT},
                {'in_port': 1, 'vlan_vid': self.V100},
                {'in_port': 3, 'vlan_vid': 0}]
            for match in matches:
                self.assertFalse(
                    self.table.is_output(match),
                    msg='Packets with incorrect vlan tags are output')

        def test_unknown_eth_src(self):
            """Test that packets from unknown macs are sent to controller.

            Untagged packets should have VLAN tags pushed before they are sent to
            the controller.
            """
            matches = [
                {'in_port': 1, 'vlan_vid': 0},
                {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.UNKNOWN_MAC},
                {
                    'in_port': 1,
                    'vlan_vid': 0,
                    'eth_src': self.P2_V200_MAC
                    },
                {'in_port': 2, 'vlan_vid': 0, 'eth_dst': self.UNKNOWN_MAC},
                {'in_port': 2, 'vlan_vid': 0},
                {
                    'in_port': 2,
                    'vlan_vid': self.V100,
                    'eth_src': self.P2_V200_MAC
                    },
                {
                    'in_port': 2,
                    'vlan_vid': self.V100,
                    'eth_src': self.UNKNOWN_MAC,
                    'eth_dst': self.P1_V100_MAC
                    },
                ]
            for match in matches:
                if match['vlan_vid'] != 0:
                    vid = match['vlan_vid']
                else:
                    vid = self.valve.dp.get_native_vlan(match['in_port']).vid
                    vid = vid | ofp.OFPVID_PRESENT
                self.assertTrue(
                    self.table.is_output(match, ofp.OFPP_CONTROLLER, vid=vid),
                    msg="Packet with unknown ethernet src not sent to controller: "
                    "{0}".format(match))

        def test_unknown_eth_dst_rule(self):
            """Test that packets with unkown eth dst addrs get flooded correctly.

            They must be output to each port on the associated vlan, with the
            correct vlan tagging. And they must not be forwarded to a port not
            on the associated vlan
            """
            self.learn_hosts()
            matches = [
                {
                    'in_port': 3,
                    'vlan_vid': self.V100,
                },
                {
                    'in_port': 2,
                    'vlan_vid': 0,
                    'eth_dst': self.P1_V100_MAC
                },
                {
                    'in_port': 1,
                    'vlan_vid': 0,
                    'eth_src': self.P1_V100_MAC
                },
                {
                    'in_port': 3,
                    'vlan_vid': self.V200,
                    'eth_src': self.P2_V200_MAC,
                }
            ]
            self.verify_flooding(matches)

        def test_known_eth_src_rule(self):
            """Test that packets with known eth src addrs are not sent to controller."""
            self.learn_hosts()
            matches = [
                {
                    'in_port': 1,
                    'vlan_vid': 0,
                    'eth_src': self.P1_V100_MAC
                    },
                {
                    'in_port': 2,
                    'vlan_vid': self.V200,
                    'eth_src': self.P2_V200_MAC
                    },
                {
                    'in_port': 3,
                    'vlan_vid': self.V200,
                    'eth_src': self.P3_V200_MAC,
                    'eth_dst': self.P2_V200_MAC
                    }
                ]
            for match in matches:
                self.assertFalse(
                    self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
                    msg="Packet ({0}) output to controller when eth_src address"
                        " is known".format(match))

        def test_known_eth_src_deletion(self):
            """Verify that when a mac changes port the old rules get deleted.

            If a mac address is seen on one port, then seen on a different port on
            the same vlan the rules associated with that mac address on previous
            port need to be deleted. IE packets with that mac address arriving on
            the old port should be output to the controller."""

            self.rcv_packet(3, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vlan_vid': 0x200,
                'ipv4_src': '10.0.0.3',
                'ipv4_dst': '10.0.0.3'})
            match = {'in_port': 2, 'vlan_vid': 0, 'eth_src': self.P2_V200_MAC}
            self.assertTrue(
                self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
                msg='eth src rule not deleted when mac seen on another port')

        def test_known_eth_dst_rule(self):
            """Test that packets with known eth dst addrs are output correctly.

            Output to the correct port with the correct vlan tagging."""
            self.learn_hosts()
            match_results = [
                ({
                    'in_port': 2,
                    'vlan_vid': self.V100,
                    'eth_dst': self.P1_V100_MAC
                    }, {
                        'out_port': 1,
                        'vlan_vid': 0
                    }),
                ({
                    'in_port': 3,
                    'vlan_vid': self.V200,
                    'eth_dst': self.P2_V200_MAC,
                    'eth_src': self.P3_V200_MAC
                    }, {
                        'out_port': 2,
                        'vlan_vid': 0,
                    })
                ]
            for match, result in match_results:
                self.assertTrue(
                    self.table.is_output(
                        match, result['out_port'], vid=result['vlan_vid']),
                    msg='packet not output to port correctly when eth dst is known')
                incorrect_ports = set(range(1, self.NUM_PORTS + 1))
                incorrect_ports.remove(result['out_port'])
                for port in incorrect_ports:
                    self.assertFalse(
                        self.table.is_output(match, port=port),
                        msg=('packet %s output to incorrect port %u when eth_dst '
                             'is known' % (match, port)))
            self.verify_expiry()

        def test_mac_vlan_separation(self):
            """Test that when a mac is seen on a second vlan the original vlan
            rules are unaffected."""
            self.learn_hosts()
            self.rcv_packet(2, 0x200, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vlan_vid': 0x200,
                'ipv4_src': '10.0.0.2',
                'ipv4_dst': '10.0.0.3'})

            # check eth_src rule
            match1 = {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC}
            self.assertFalse(
                self.table.is_output(match1, ofp.OFPP_CONTROLLER),
                msg=('mac address being seen on a vlan affects eth_src rule on '
                     'other vlan'))

            # check eth_dst rule
            match2 = {'in_port': 3, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}
            self.assertTrue(
                self.table.is_output(match2, port=1, vid=0),
                msg=('mac address being seen on a vlan affects eth_dst rule on '
                     'other vlan'))
            for port in (2, 4):
                self.assertFalse(
                    self.table.is_output(match2, port=port),
                    msg=('mac address being seen on a vlan affects eth_dst rule on '
                         'other vlan'))

        def test_known_eth_dst_deletion(self):
            """Test that eth_dst rules are deleted when the mac is learned on
            another port.

            This should only occur when the mac is seen on the same vlan."""
            self.rcv_packet(2, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'ipv4_src': '10.0.0.2',
                'ipv4_dst': '10.0.0.3'})
            match = {'in_port': 3, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}
            self.assertTrue(
                self.table.is_output(match, port=2, vid=self.V100),
                msg='Packet not output correctly after mac is learnt on new port')
            self.assertFalse(
                self.table.is_output(match, port=1),
                msg='Packet output on old port after mac is learnt on new port')

        def test_port_delete_eth_dst(self):
            """Test that when a port is disabled packets are correctly output. """
            match = {'in_port': 2, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}

            valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            ofmsgs = self.valve.port_delete(port_num=1)
            self.apply_ofmsgs(ofmsgs)

            # Check packets are output to each port on vlan
            for port in valve_vlan.get_ports():
                if port.number != match['in_port'] and port.running():
                    if valve_vlan.port_is_tagged(port):
                        vid = valve_vlan.vid | ofp.OFPVID_PRESENT
                    else:
                        vid = 0
                    self.assertTrue(
                        self.table.is_output(match, port=port.number, vid=vid),
                        msg=('packet %s with eth dst learnt on deleted port not output '
                             'correctly on vlan %u to port %u' % (
                                 match, valve_vlan.vid, port.number)))

        def test_port_down_eth_src_removal(self):
            """Test that when a port goes down and comes back up learnt mac
            addresses are deleted."""

            match = {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC}
            self.flap_port(1)
            self.assertTrue(
                self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
                msg='Packet not output to controller after port bounce')

        def test_port_add_input(self):
            """Test that when a port is enabled packets are input correctly."""

            match = {'in_port': 1, 'vlan_vid': 0}
            self.apply_ofmsgs(
                self.valve.port_delete(port_num=1))
            self.assertFalse(
                self.table.is_output(match, port=2, vid=self.V100),
                msg='Packet output after port delete')

            self.apply_ofmsgs(
                self.valve.port_add(port_num=1))
            self.assertTrue(
                self.table.is_output(match, port=2, vid=self.V100),
                msg='Packet not output after port add')

        def test_dp_acl_deny(self):
            """Test DP acl denies forwarding"""
            acl_config = """
dps:
    s1:
        dp_acls: [drop_non_ospf_ipv4]
%s
        interfaces:
            p2:
                number: 2
                native_vlan: v200
            p3:
                number: 3
                tagged_vlans: [v200]
vlans:
    v200:
        vid: 0x200
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                meter: testmeter
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                output:
                    set_fields:
                        - eth_dst: 00:00:00:00:00:01
                allow: 0
meters:
    testmeter:
        meter_id: 99
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 1
                    }
                ]
""" % DP1_CONFIG

            drop_match = {
                'in_port': 2,
                'vlan_vid': 0,
                'eth_type': 0x800,
                'ipv4_dst': '192.0.2.1'}
            accept_match = {
                'in_port': 2,
                'vlan_vid': 0,
                'eth_type': 0x800,
                'ipv4_dst': '224.0.0.5'}
            self.update_config(acl_config)
            self.flap_port(2)
            self.assertFalse(
                self.table.is_output(drop_match),
                msg='packet not blocked by ACL')
            self.assertTrue(
                self.table.is_output(accept_match, port=3, vid=self.V200),
                msg='packet not allowed by ACL')

        def test_port_acl_deny(self):
            """Test that port ACL denies forwarding."""
            acl_config = """
dps:
    s1:
%s
        interfaces:
            p2:
                number: 2
                native_vlan: v200
                acl_in: drop_non_ospf_ipv4
            p3:
                number: 3
                tagged_vlans: [v200]
vlans:
    v200:
        vid: 0x200
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                meter: testmeter
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
meters:
    testmeter:
        meter_id: 99
        entry:
            flags: "KBPS"
            bands:
                [
                    {
                        type: "DROP",
                        rate: 1
                    }
                ]
""" % DP1_CONFIG

            drop_match = {
                'in_port': 2,
                'vlan_vid': 0,
                'eth_type': 0x800,
                'ipv4_dst': '192.0.2.1'}
            accept_match = {
                'in_port': 2,
                'vlan_vid': 0,
                'eth_type': 0x800,
                'ipv4_dst': '224.0.0.5'}
            # base case
            for match in (drop_match, accept_match):
                self.assertTrue(
                    self.table.is_output(match, port=3, vid=self.V200),
                    msg='Packet not output before adding ACL')

            self.update_config(acl_config)
            self.assertFalse(
                self.table.is_output(drop_match),
                msg='packet not blocked by ACL')
            self.assertTrue(
                self.table.is_output(accept_match, port=3, vid=self.V200),
                msg='packet not allowed by ACL')

        def test_lldp_beacon(self):
            """Test LLDP beacon service."""
            # TODO: verify LLDP packet content.
            self.assertTrue(self.valve.fast_advertise(self.mock_time(10), None))

        def test_unknown_port(self):
            """Test port status change for unknown port handled."""
            self.set_port_up(99)

        def test_port_modify(self):
            """Set port status modify."""
            for port_status in (0, 1):
                self.apply_ofmsgs(self.valve.port_status_handler(
                    1, ofp.OFPPR_MODIFY, port_status, [])[self.valve])

        def test_unknown_port_status(self):
            """Test unknown port status message."""
            known_messages = set([ofp.OFPPR_MODIFY, ofp.OFPPR_ADD, ofp.OFPPR_DELETE])
            unknown_messages = list(set(range(0, len(known_messages) + 1)) - known_messages)
            self.assertTrue(unknown_messages)
            self.assertFalse(self.valve.port_status_handler(
                1, unknown_messages[0], 1, []).get(self.valve, []))

        def test_move_port(self):
            """Test host moves a port."""
            self.rcv_packet(2, 0x200, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vlan_vid': 0x200,
                'ipv4_src': '10.0.0.2',
                'ipv4_dst': '10.0.0.3'})
            self.rcv_packet(4, 0x200, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vlan_vid': 0x200,
                'ipv4_src': '10.0.0.2',
                'ipv4_dst': '10.0.0.3'})

        def test_bgp_route_change(self):
            """Test BGP route change handler."""
            nexthop = '10.0.0.1'
            prefix = '192.168.1.1/32'
            add_event = RouteAddition(
                IPPrefix.from_string(prefix),
                IPAddress.from_string(nexthop),
                '65001',
                'IGP'
            )
            del_event = RouteRemoval(
                IPPrefix.from_string(prefix),
            )
            self.bgp._bgp_route_handler(  # pylint: disable=protected-access
                add_event,
                faucet_bgp.BgpSpeakerKey(self.DP_ID, 0x100, 4))
            self.bgp._bgp_route_handler(  # pylint: disable=protected-access
                del_event,
                faucet_bgp.BgpSpeakerKey(self.DP_ID, 0x100, 4))
            self.bgp._bgp_up_handler(nexthop, 65001)  # pylint: disable=protected-access
            self.bgp._bgp_down_handler(nexthop, 65001)  # pylint: disable=protected-access

        def test_packet_in_rate(self):
            """Test packet in rate limit triggers."""
            now = self.mock_time(10)
            for _ in range(self.valve.dp.ignore_learn_ins * 2 + 1):
                if self.valve.rate_limit_packet_ins(now):
                    return
            self.fail('packet in rate limit not triggered')

        def test_ofdescstats_handler(self):
            """Test OFDescStatsReply handler."""
            body = parser.OFPDescStats(
                mfr_desc=u'test_mfr_desc'.encode(),
                hw_desc=u'test_hw_desc'.encode(),
                sw_desc=u'test_sw_desc'.encode(),
                serial_num=u'99'.encode(),
                dp_desc=u'test_dp_desc'.encode())
            self.valve.ofdescstats_handler(body)
            invalid_body = parser.OFPDescStats(
                mfr_desc=b'\x80',
                hw_desc=b'test_hw_desc',
                sw_desc=b'test_sw_desc',
                serial_num=b'99',
                dp_desc=b'test_dp_desc')
            self.valve.ofdescstats_handler(invalid_body)

        def test_get_config_dict(self):
            """Test API call for DP config."""
            # TODO: test actual config contents.
            self.assertTrue(self.valve.get_config_dict())
            self.assertTrue(self.valve.dp.get_tables())


    class ValveTestStackedRouting(ValveTestSmall):
        """Test inter-vlan routing with stacking capabilities in an IPV4 network"""

        V100 = 0x100
        V200 = 0x200
        VLAN100_FAUCET_MAC = '00:00:00:00:00:11'
        VLAN200_FAUCET_MAC = '00:00:00:00:00:22'

        VLAN100_FAUCET_VIPS = ''
        VLAN100_FAUCET_VIP_SPACE = ''
        VLAN200_FAUCET_VIPS = ''
        VLAN200_FAUCET_VIP_SPACE = ''

        V100_HOSTS = []
        V200_HOSTS = []

        def base_config(self):
            """Create the base config"""
            self.V100_HOSTS = [1, 2, 3, 4]
            self.V200_HOSTS = [1, 2, 3, 4]
            return """
    routers:
        router1:
            vlans: [vlan100, vlan200]
    dps:
        s1:
            hardware: 'GenericTFM'
            dp_id: 1
            stack: {priority: 1}
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s2, port: 3}
        s2:
            dp_id: 2
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s1, port: 3}
                4:
                    stack: {dp: s3, port: 3}
        s3:
            dp_id: 3
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s2, port: 4}
                4:
                    stack: {dp: s4, port: 3}
        s4:
            dp_id: 4
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s3, port: 4}
    """

        def create_config(self):
            """Create the config file"""
            self.CONFIG = """
    vlans:
        vlan100:
            vid: 0x100
            faucet_mac: '%s'
            faucet_vips: ['%s']
        vlan200:
            vid: 0x200
            faucet_mac: '%s'
            faucet_vips: ['%s']
    %s
           """ % (self.VLAN100_FAUCET_MAC, self.VLAN100_FAUCET_VIP_SPACE,
                  self.VLAN200_FAUCET_MAC, self.VLAN200_FAUCET_VIP_SPACE,
                  self.base_config())

        def setup_stack_routing(self):
            """Create a stacking config file."""
            self.create_config()
            self.setup_valve(self.CONFIG)
            for valve in self.valves_manager.valves.values():
                valve.dp.dyn_running = True
                for port in valve.dp.ports.values():
                    port.dyn_finalized = False
                    port.enabled = True
                    port.dyn_phys_up = True
                    port.dyn_finalized = True

        @staticmethod
        def create_mac(vindex, host):
            """Create a MAC address string"""
            return '00:00:00:0%u:00:0%u' % (vindex, host)

        @staticmethod
        def create_ip(vindex, host):
            """Create a IP address string"""
            return '10.0.%u.%u' % (vindex, host)

        @staticmethod
        def get_eth_type():
            """Returns IPV4 ether type"""
            return valve_of.ether.ETH_TYPE_IP

        def create_match(self, vindex, host, faucet_mac, faucet_vip, code):
            """Create an ARP reply message"""
            return {
                'eth_src': self.create_mac(vindex, host),
                'eth_dst': faucet_mac,
                'arp_code': code,
                'arp_source_ip': self.create_ip(vindex, host),
                'arp_target_ip': faucet_vip
            }

        def verify_router_cache(self, ip_match, eth_match, vid, dp_id):
            """Verify router nexthop cache stores correct values"""
            host_valve = self.valves_manager.valves[dp_id]
            for valve in self.valves_manager.valves.values():
                valve_vlan = valve.dp.vlans[vid]
                route_manager = valve._route_manager_by_eth_type.get(  # pylint: disable=protected-access
                    self.get_eth_type(), None)
                vlan_nexthop_cache = route_manager._vlan_nexthop_cache(valve_vlan)  # pylint: disable=protected-access
                self.assertTrue(vlan_nexthop_cache)
                host_ip = ipaddress.ip_address(ip_match)
                # Check IP address is properly cached
                self.assertIn(host_ip, vlan_nexthop_cache)
                nexthop = vlan_nexthop_cache[host_ip]
                # Check MAC address is properly cached
                self.assertEqual(eth_match, nexthop.eth_src)
                if host_valve != valve:
                    # Check the proper nexthop port is cached
                    expected_port = valve.dp.shortest_path_port(host_valve.dp.name)
                    self.assertEqual(expected_port, nexthop.port)

        def test_router_cache_learn_hosts(self):
            """Have all router caches contain proper host nexthops"""
            # Learn Vlan100 hosts
            for host in self.V100_HOSTS:
                self.valve_rcv_packet(1, self.V100, self.create_match(
                    1, host, self.VLAN100_FAUCET_MAC,
                    self.VLAN100_FAUCET_VIPS, arp.ARP_REPLY), host)
                self.verify_router_cache(
                    self.create_ip(1, host), self.create_mac(1, host), self.V100, host)
            # Learn Vlan200 hosts
            for host in self.V200_HOSTS:
                self.valve_rcv_packet(2, self.V200, self.create_match(
                    2, host, self.VLAN200_FAUCET_MAC,
                    self.VLAN200_FAUCET_VIPS, arp.ARP_REPLY), host)
                self.verify_router_cache(
                    self.create_ip(2, host), self.create_mac(2, host), self.V200, host)
