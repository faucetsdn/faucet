#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=.. python3 ./test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2018 The Contributors
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

import ipaddress
import logging
import os
import unittest
import tempfile
import shutil
import socket
import time

from ryu.controller import dpset
from ryu.controller.ofp_event import EventOFPMsgBase
from ryu.lib import mac
from ryu.lib.packet import arp, ethernet, icmp, icmpv6, ipv4, ipv6, lldp, slow, packet, vlan
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from prometheus_client import CollectorRegistry

from beka.route import RouteAddition, RouteRemoval
from beka.ip import IPAddress, IPPrefix

from faucet import faucet
from faucet import faucet_bgp
from faucet import faucet_dot1x
from faucet import faucet_experimental_api
from faucet import faucet_experimental_event
from faucet import faucet_metrics
from faucet import valves_manager
from faucet import valve_of
from faucet import valve_packet
from faucet import valve_util
from faucet.valve import TfmValve

from fakeoftable import FakeOFTable


FAUCET_MAC = '0e:00:00:00:00:01'

# TODO: fix fake OF table implementation for in_port filtering
# (ie. do not output to in_port)
DP1_CONFIG = """
        dp_id: 1
        ignore_learn_ins: 100
        combinatorial_port_flood: True
        ofchannel_log: '/dev/null'
        pipeline_config_dir: '%s/../../etc/faucet'
        packetin_pps: 99
        lldp_beacon:
            send_interval: 1
            max_per_interval: 1
""" % os.path.dirname(os.path.realpath(__file__))

IDLE_DP1_CONFIG = """
        use_idle_timeout: True
""" + DP1_CONFIG

GROUP_DP1_CONFIG = """
        group_table: True
""" + DP1_CONFIG

GROUP_ROUTING_DP1_CONFIG = """
        group_table_routing: True
""" + DP1_CONFIG

CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
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
        hardware: 'Open vSwitch'
        dp_id: 0xdeadbeef
        interfaces:
            p1:
                number: 1
                native_vlan: v100
    s3:
        hardware: 'Open vSwitch'
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
                stack:
                    dp: s4
                    port: 5
    s4:
        hardware: 'Open vSwitch'
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
        arp_code = arp.ARP_REQUEST
        if pkt['eth_dst'] == FAUCET_MAC:
            arp_code = arp.ARP_REPLY
        layers.append(arp.arp(
            src_ip=pkt['arp_source_ip'], dst_ip=pkt['arp_target_ip'], opcode=arp_code))
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
            actor_state_synchronization=1,
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


class ValveTestBases:
    """Insulate test base classes from unittest so we can reuse base clases."""


    class ValveTestSmall(unittest.TestCase): # pytype: disable=module-attr
        """Base class for all Valve unit tests."""

        DP = 's1'
        DP_ID = 1
        NUM_PORTS = 5
        NUM_TABLES = 9
        P1_V100_MAC = '00:00:00:01:00:01'
        P2_V200_MAC = '00:00:00:02:00:02'
        P3_V200_MAC = '00:00:00:02:00:03'
        P1_V300_MAC = '00:00:00:03:00:01'
        UNKNOWN_MAC = '00:00:00:04:00:04'
        V100 = 0x100|ofp.OFPVID_PRESENT
        V200 = 0x200|ofp.OFPVID_PRESENT
        V300 = 0x300|ofp.OFPVID_PRESENT
        LOGNAME = 'faucet'
        dot1x = None
        last_flows_to_dp = {}
        valve = None
        valves_manager = None
        metrics = None
        bgp = None
        table = None
        logger = None
        tmpdir = None
        faucet_event_sock = None
        registry = None
        sock = None
        notifier = None
        config_file = None
        _icmp_payload = bytes('A'*8, encoding='UTF-8') # pytype: disable=wrong-keyword-args

        def setup_valve(self, config):
            """Set up test DP with config."""
            self.tmpdir = tempfile.mkdtemp()
            self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
            self.faucet_event_sock = os.path.join(self.tmpdir, 'event.sock')
            self.table = FakeOFTable(self.NUM_TABLES)
            logfile = os.path.join(self.tmpdir, 'faucet.log')
            self.logger = valve_util.get_logger(self.LOGNAME, logfile, logging.DEBUG, 0)
            self.registry = CollectorRegistry()
            # TODO: verify Prometheus variables
            self.metrics = faucet_metrics.FaucetMetrics(reg=self.registry) # pylint: disable=unexpected-keyword-arg
            # TODO: verify events
            self.notifier = faucet_experimental_event.FaucetExperimentalEventNotifier(
                self.faucet_event_sock, self.metrics, self.logger)
            self.bgp = faucet_bgp.FaucetBgp(self.logger, self.metrics, self.send_flows_to_dp_by_id)
            self.dot1x = faucet_dot1x.FaucetDot1x(
                self.logger, self.metrics, self.send_flows_to_dp_by_id)
            self.valves_manager = valves_manager.ValvesManager(
                self.LOGNAME, self.logger, self.metrics, self.notifier,
                self.bgp, self.dot1x, self.send_flows_to_dp_by_id)
            self.last_flows_to_dp[self.DP_ID] = []
            self.notifier.start()
            self.update_config(config)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(self.faucet_event_sock)
            self.connect_dp()

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

        def get_prom(self, var, labels=None):
            """Return a Prometheus variable value."""
            if labels is None:
                labels = {}
            labels.update({
                'dp_name': self.DP,
                'dp_id': '0x%x' % self.DP_ID})
            return self.registry.get_sample_value(var, labels)

        def prom_inc(self, func, var, labels=None):
            """Check Prometheus variable increments by 1 after calling a function."""
            before = self.get_prom(var, labels)
            func()
            self.assertTrue(before + 1, self.get_prom(var, labels))

        def send_flows_to_dp_by_id(self, valve, flows):
            """Callback for ValvesManager to simulate sending flows to DP."""
            valve = self.valves_manager.valves[self.DP_ID]
            prepared_flows = valve.prepare_send_flows(flows)
            self.last_flows_to_dp[valve.dp.dp_id] = prepared_flows

        def update_config(self, config):
            """Update FAUCET config with config as text."""
            self.assertFalse(self.valves_manager.config_watcher.files_changed())
            existing_config = os.path.exists(self.config_file)
            with open(self.config_file, 'w') as config_file:
                config_file.write(config)
            if existing_config:
                self.assertTrue(self.valves_manager.config_watcher.files_changed())
            self.last_flows_to_dp[self.DP_ID] = []
            self.valves_manager.request_reload_configs(time.time(), self.config_file)
            self.valve = self.valves_manager.valves[self.DP_ID]
            if self.DP_ID in self.last_flows_to_dp:
                reload_ofmsgs = self.last_flows_to_dp[self.DP_ID]
                self.table.apply_ofmsgs(reload_ofmsgs)

        def connect_dp(self):
            """Call DP connect and set all ports to up."""
            discovered_up_ports = [port_no for port_no in range(1, self.NUM_PORTS + 1)]
            self.table.apply_ofmsgs(
                self.valve.switch_features(None) +
                self.valve.datapath_connect(time.time(), discovered_up_ports))
            for port_no in discovered_up_ports:
                self.set_port_up(port_no)
            self.assertTrue(self.valve.dp.to_conf())

        def set_port_down(self, port_no):
            """Set port status of port to down."""
            self.table.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_DELETE, ofp.OFPPS_LINK_DOWN))

        def set_port_up(self, port_no):
            """Set port status of port to up."""
            self.table.apply_ofmsgs(self.valve.port_status_handler(
                port_no, ofp.OFPPR_ADD, 0))

        def flap_port(self, port_no):
            """Flap op status on a port."""
            self.set_port_down(port_no)
            self.set_port_up(port_no)

        @staticmethod
        def packet_outs_from_flows(flows):
            """Return flows that are packetout actions."""
            return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPPacketOut)]

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
            now = time.time()
            for _ in range(self.valve.dp.max_host_fib_retry_count + 1):
                now += (self.valve.dp.timeout * 2)
                self.valve.state_expire(now)
                self.valve.resolve_gateways(now)
            # TODO: verify state expired

        def verify_flooding(self, matches):
            """Verify flooding for a packet, depending on the DP implementation."""

            combinatorial_port_flood = self.valve.dp.combinatorial_port_flood
            if self.valve.dp.group_table:
                combinatorial_port_flood = False

            def _verify_flood_to_port(match, port, valve_vlan, port_number=None):
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid|ofp.OFPVID_PRESENT
                else:
                    vid = 0
                if port_number is None:
                    port_number = port.number
                return self.table.is_output(match, port=port_number, vid=vid)

            for match in matches:
                in_port_number = match['in_port']
                in_port = self.valve.dp.ports[in_port_number]

                if ('vlan_vid' in match and
                        match['vlan_vid'] & ofp.OFPVID_PRESENT is not 0):
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

                # Packet must be flooded to all ports on the VLAN.
                if not self.valve.dp.stack or 'priority' in self.valve.dp.stack:
                    for port in valve_vlan.get_ports():
                        output = _verify_flood_to_port(match, port, valve_vlan)
                        if port == in_port:
                            self.assertNotEqual(
                                combinatorial_port_flood, output,
                                msg=('flooding to in_port (%s) not '
                                     'compatible with flood mode (%s)') % (
                                         output, combinatorial_port_flood))
                            continue
                        self.assertTrue(
                            output,
                            msg=('%s with unknown eth_dst not flooded'
                                 ' on VLAN %u to port %u' % (
                                     match, valve_vlan.vid, port.number)))

                # Packet must not be flooded to ports not on the VLAN.
                for port in remaining_ports:
                    if port.stack:
                        self.assertTrue(
                            self.table.is_output(match, port=port.number),
                            msg=('Uknown eth_dst not flooded to stack port %s' % port))
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
            now = time.time()
            self.prom_inc(
                partial(self.valves_manager.valve_packet_in, now, self.valve, msg),
                'of_packet_ins')
            rcv_packet_ofmsgs = self.last_flows_to_dp[self.DP_ID]
            self.table.apply_ofmsgs(rcv_packet_ofmsgs)
            for valve_service in (
                    'resolve_gateways', 'advertise',
                    'send_lldp_beacons', 'state_expire'):
                self.valves_manager.valve_flow_services(
                    now, valve_service)
            self.valves_manager.update_metrics(now)
            return rcv_packet_ofmsgs


    class ValveTestBig(ValveTestSmall):
        """Test basic switching/L2/L3 functions."""

        def setUp(self):
            self.setup_valve(CONFIG)

        def test_get_config_dict(self):
            """Test API call for DP config."""
            # TODO: test actual config contents.
            self.assertTrue(self.valve.get_config_dict())
            self.assertTrue(self.valve.dp.get_tables())

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
            # TODO: verify DP state change.
            self.valve.datapath_disconnect()

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
            discovered_up_ports = [port_no for port_no in range(1, self.NUM_PORTS + 1)]
            flows = self.valve.datapath_connect(time.time(), discovered_up_ports)
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

        def test_arp_for_controller(self):
            """ARP request for controller VIP."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})
            # TODO: check ARP reply is valid
            self.assertTrue(self.packet_outs_from_flows(arp_replies))

        def test_arp_reply_from_host(self):
            """ARP reply for host."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})
            # TODO: check ARP reply is valid
            self.assertTrue(arp_replies)
            self.assertFalse(self.packet_outs_from_flows(arp_replies))

        def test_nd_for_controller(self):
            """IPv6 ND for controller VIP."""
            dst_ip = ipaddress.IPv6Address('fc00::1:254')
            nd_mac = valve_packet.ipv6_link_eth_mcast(dst_ip)
            ip_gw_mcast = valve_packet.ipv6_solicited_node_from_ucast(dst_ip)
            nd_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': nd_mac,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:1',
                'ipv6_dst': str(ip_gw_mcast),
                'neighbor_solicit_ip': str(dst_ip)})
            # TODO: check ND reply is valid
            self.assertTrue(self.packet_outs_from_flows(nd_replies))

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
                'echo_request_data': bytes(
                    'A'*8, encoding='UTF-8')}) # pytype: disable=wrong-keyword-args
            # TODO: check ping response
            self.assertTrue(self.packet_outs_from_flows(echo_replies))

        def test_add_del_route(self):
            """IPv4 add/del of a route."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
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
                    'A'*8, encoding='UTF-8')}) # pytype: disable=wrong-keyword-args
            # TODO: verify learning rule contents
            # We want to know this host was learned we did not get packet outs.
            self.assertTrue(fib_route_replies)
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
                'echo_request_data': self._icmp_payload})
            # TODO: verify learning rule contents
            # We want to know this host was learned we did not get packet outs.
            self.assertTrue(fib_route_replies)
            self.assertFalse(self.packet_outs_from_flows(fib_route_replies))
            self.verify_expiry()

        def test_icmp_ping_unknown_neighbor(self):
            """IPv4 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.99',
                'echo_request_data': self._icmp_payload})
            # TODO: check proactive neighbor resolution
            self.assertTrue(self.packet_outs_from_flows(echo_replies))

        def test_icmp_ping6_unknown_neighbor(self):
            """IPv4 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:2',
                'ipv6_dst': 'fc00::1:4',
                'echo_request_data': self._icmp_payload})
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
                'echo_request_data': self._icmp_payload})
            # TODO: check ping response
            self.assertTrue(self.packet_outs_from_flows(echo_replies))

        def test_invalid_vlan(self):
            """Test that packets with incorrect vlan tagging get dropped."""

            matches = [
                {'in_port': 1, 'vlan_vid': 18|ofp.OFPVID_PRESENT},
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
                {'in_port': 1, 'vlan_vid': 0, 'eth_src' : self.UNKNOWN_MAC},
                {
                    'in_port': 1,
                    'vlan_vid': 0,
                    'eth_src' : self.P2_V200_MAC
                    },
                {'in_port': 2, 'vlan_vid': 0, 'eth_dst' : self.UNKNOWN_MAC},
                {'in_port': 2, 'vlan_vid': 0},
                {
                    'in_port': 2,
                    'vlan_vid': self.V100,
                    'eth_src' : self.P2_V200_MAC
                    },
                {
                    'in_port': 2,
                    'vlan_vid': self.V100,
                    'eth_src' : self.UNKNOWN_MAC,
                    'eth_dst' : self.P1_V100_MAC
                    },
                ]
            for match in matches:
                if match['vlan_vid'] != 0:
                    vid = match['vlan_vid']
                else:
                    vid = self.valve.dp.get_native_vlan(match['in_port']).vid
                    vid = vid|ofp.OFPVID_PRESENT
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

        def test_mac_learning_vlan_separation(self):
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

        def test_known_eth_dst_rule_deletion(self):
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

        def test_port_delete_eth_dst_removal(self):
            """Test that when a port is disabled packets are correctly output. """
            match = {'in_port': 2, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}

            valve_vlan = self.valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            ofmsgs = self.valve.port_delete(port_num=1)
            self.table.apply_ofmsgs(ofmsgs)

            # Check packets are output to each port on vlan
            for port in valve_vlan.get_ports():
                if port.number != match['in_port'] and port.running():
                    if valve_vlan.port_is_tagged(port):
                        vid = valve_vlan.vid|ofp.OFPVID_PRESENT
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
            self.table.apply_ofmsgs(
                self.valve.port_delete(port_num=1))
            self.assertFalse(
                self.table.is_output(match, port=2, vid=self.V100),
                msg='Packet output after port delete')

            self.table.apply_ofmsgs(
                self.valve.port_add(port_num=1))
            self.assertTrue(
                self.table.is_output(match, port=2, vid=self.V100),
                msg='Packet not output after port add')

        def test_dp_acl_deny(self):
            acl_config = """
dps:
    s1:
        hardware: 'Open vSwitch'
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
        hardware: 'Open vSwitch'
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
            self.assertTrue(self.valve.send_lldp_beacons(time.time()))

        def test_unknown_port(self):
            """Test port status change for unknown port handled."""
            self.set_port_up(99)

        def test_port_modify(self):
            """Set port status modify."""
            for port_status in (0, 1):
                self.table.apply_ofmsgs(self.valve.port_status_handler(
                    1, ofp.OFPPR_MODIFY, port_status))

        def test_unknown_port_status(self):
            """Test unknown port status message."""
            known_messages = set([ofp.OFPPR_MODIFY, ofp.OFPPR_ADD, ofp.OFPPR_DELETE])
            unknown_messages = list(set(range(0, len(known_messages) + 1)) - known_messages)
            self.assertTrue(unknown_messages)
            self.assertFalse(self.valve.port_status_handler(
                1, unknown_messages[0], 1))

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
            self.bgp._bgp_route_handler(
                add_event,
                faucet_bgp.BgpSpeakerKey(self.DP_ID, 0x100, 4))
            self.bgp._bgp_route_handler(
                del_event,
                faucet_bgp.BgpSpeakerKey(self.DP_ID, 0x100, 4))
            self.bgp._bgp_up_handler(nexthop, 65001)
            self.bgp._bgp_down_handler(nexthop, 65001)

        def test_packet_in_rate(self):
            """Test packet in rate limit triggers."""
            now = time.time()
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


class ValveTestCase(ValveTestBases.ValveTestBig):
    """Run complete set of basic tests."""

    pass


class ValveChangePortCase(ValveTestBases.ValveTestSmall):
    """Test changes to config on ports."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: True
""" % DP1_CONFIG

    LESS_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x200
                permanent_learn: False
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_delete_port(self):
        """Test port can be deleted."""
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3',
            'vid': 0x200})
        self.update_config(self.LESS_CONFIG)


class ValveACLTestCase(ValveTestBases.ValveTestSmall):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        acl_config = """
dps:
    s1:
        hardware: 'Open vSwitch'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                native_vlan: v300
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        acl_in: drop_non_ospf_ipv4
    v300:
        vid: 0x300
acls:
    drop_non_ospf_ipv4:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
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
        self.flap_port(2)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='Packet not allowed by ACL')


class ValveRootStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacking/forwarding."""

    DP = 's3'
    DP_ID = 0x3

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_stack_learn(self):
        """Test host learning on stack root."""
        self.rcv_packet(1, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})
        self.rcv_packet(5, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x300,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})

    def test_stack_flood(self):
        """Test packet flooding when stacking."""
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V300_MAC
            }]
        self.verify_flooding(matches)


class ValveEdgeStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacking/forwarding."""

    DP = 's4'
    DP_ID = 0x4

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_stack_learn(self):
        """Test host learning on non-root switch."""
        self.rcv_packet(1, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})
        self.rcv_packet(5, 0x300, {
            'eth_src': self.P1_V300_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x300,
            'ipv4_src': '10.0.0.1',
            'ipv4_dst': '10.0.0.2'})

    def test_stack_flood(self):
        """Test packet flooding when stacking."""
        matches = [
            {
                'in_port': 1,
                'vlan_vid': 0,
                'eth_src': self.P1_V300_MAC
            }]
        self.verify_flooding(matches)


class ValveStackProbeTestCase(ValveTestBases.ValveTestSmall):
    """Test stack link probing."""

    CONFIG = """
dps:
    s1:
%s
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: s2
                    port: 1
            2:
                stack:
                    dp: s2
                    port: 2
            3:
                native_vlan: v100
    s2:
        hardware: 'Open vSwitch'
        dp_id: 0x2
        lldp_beacon:
            send_interval: 5
            max_per_interval: 1
        interfaces:
            1:
                stack:
                    dp: s1
                    port: 1
            2:
                stack:
                    dp: s1
                    port: 2
            3:
                native_vlan: v100
    s3:
        dp_id: 0x3
        interfaces:
            1:
                native_vlan: v100
vlans:
    v100:
        vid: 100
    """ % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def rcv_lldp(self, other_dp, other_port):
        """Receive an LLDP packet"""
        tlvs = []
        tlvs.extend(valve_packet.faucet_lldp_tlvs(other_dp))
        tlvs.extend(valve_packet.faucet_lldp_stack_state_tlvs(other_dp, other_port))
        self.rcv_packet(1, 0, {
            'eth_src': FAUCET_MAC,
            'eth_dst': lldp.LLDP_MAC_NEAREST_BRIDGE,
            'port_id': other_port.number,
            'chassis_id': FAUCET_MAC,
            'system_name': other_dp.name,
            'org_tlvs': tlvs})

    def test_stack_probe(self):
        """Test probing works correctly."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        self.valve.update_stack_link_states(time.time())
        self.assertTrue(stack_port.is_stack_down())
        for change_func, check_func in [
                ('stack_init', 'is_stack_init'),
                ('stack_up', 'is_stack_up'),
                ('stack_down', 'is_stack_down')]:
            getattr(other_port, change_func)()
            self.rcv_lldp(other_dp, other_port)
            self.assertTrue(getattr(stack_port, check_func)())

    def test_stack_miscabling(self):
        """Test probing stack with miscabling."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        wrong_port = other_dp.ports[2]
        wrong_dp = self.valves_manager.valves[3].dp
        for remote_dp, remote_port in [
                (wrong_dp, other_port),
                (other_dp, wrong_port)]:
            self.rcv_lldp(other_dp, other_port)
            self.assertTrue(stack_port.is_stack_init())
            self.rcv_lldp(remote_dp, remote_port)
            self.assertTrue(stack_port.is_stack_down())

    def test_stack_lost_lldp(self):
        """Test stacking when LLDP packets get dropped"""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        self.rcv_lldp(other_dp, other_port)
        self.assertTrue(stack_port.is_stack_init())
        self.valve.update_stack_link_states(time.time() + 300) # simulate packet loss
        self.assertTrue(stack_port.is_stack_down())


class ValveGroupRoutingTestCase(ValveTestBases.ValveTestSmall):
    """Tests for datapath with group support."""

    CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
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
""" % GROUP_ROUTING_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_host_ipv4_fib_route(self):
        """Test learning a FIB rule for an IPv4 host."""
        fib_route_replies = self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vid': 0x100,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.4',
            'echo_request_data': self._icmp_payload})
        # TODO: verify learning rule contents
        # We want to know this host was learned we did not get packet outs.
        self.assertTrue(fib_route_replies)
        self.assertFalse(self.packet_outs_from_flows(fib_route_replies))


class ValveGroupTestCase(ValveTestBases.ValveTestSmall):
    """Tests for datapath with group support."""

    CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
""" % GROUP_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

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


class ValveIdleLearnTestCase(ValveTestBases.ValveTestSmall):
    """Smoke test for idle-flow based learning. This feature is not currently reliable."""

    CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
""" % IDLE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_known_eth_src_rule(self):
        """Test removal flow handlers."""
        self.learn_hosts()
        self.assertTrue(
            self.valve.flow_timeout(
                time.time(),
                self.valve.dp.tables['eth_dst'].table_id,
                {'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}))
        self.assertFalse(
            self.valve.flow_timeout(
                time.time(),
                self.valve.dp.tables['eth_src'].table_id,
                {'vlan_vid': self.V100, 'in_port': 1, 'eth_src': self.P1_V100_MAC}))


class ValveLACPTestCase(ValveTestBases.ValveTestSmall):
    """Test LACP."""

    CONFIG = """
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                tagged_vlans: [v300]
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_lacp(self):
        """Test LACP comes up."""
        # TODO: verify LACP state
        self.rcv_packet(1, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02'})
        self.learn_hosts()
        self.verify_expiry()


class ValveReloadConfigTestCase(ValveTestBases.ValveTestBig):
    """Repeats the tests after a config reload."""

    def setUp(self):
        super(ValveReloadConfigTestCase, self).setUp()
        self.flap_port(1)
        self.update_config(CONFIG)


class ValveMirrorTestCase(ValveTestBases.ValveTestBig):
    """Test ACL and interface mirroring."""
    # TODO: check mirror packets are present/correct

    CONFIG = """
acls:
    mirror_ospf:
        - rule:
            nw_dst: '224.0.0.5'
            dl_type: 0x800
            actions:
                mirror: p5
                allow: 1
        - rule:
            dl_type: 0x800
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
dps:
    s1:
        hardware: 'GenericTFM'
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lldp_beacon:
                    enable: True
                    system_name: "faucet"
                    port_descr: "first_port"
                acls_in: [mirror_ospf]
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
                output_only: True
                mirror: 4
vlans:
    v100:
        vid: 0x100
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
        bgp_port: 9179
        bgp_server_addresses: ['127.0.0.1']
        bgp_as: 1
        bgp_routerid: '1.1.1.1'
        bgp_neighbor_addresses: ['127.0.0.1']
        bgp_neighbor_as: 2
        bgp_connect_mode: 'passive'
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)


class RyuAppSmokeTest(unittest.TestCase): # pytype: disable=module-attr
    """Test bare instantiation of controller classes."""

    @staticmethod
    def _fake_dp():
        datapath = namedtuple('datapath', ['id', 'close'])(0, lambda: None)
        return datapath

    def test_faucet(self):
        """Test FAUCET can be initialized."""
        os.environ['FAUCET_CONFIG'] = '/dev/null'
        os.environ['FAUCET_LOG'] = '/dev/null'
        os.environ['FAUCET_EXCEPTION_LOG'] = '/dev/null'
        ryu_app = faucet.Faucet(
            dpset={},
            faucet_experimental_api=faucet_experimental_api.FaucetExperimentalAPI(),
            reg=CollectorRegistry())
        ryu_app.reload_config(None)
        self.assertFalse(ryu_app._config_files_changed())
        ryu_app.metric_update(None)
        ryu_app.get_config()
        ryu_app.get_tables(0)
        event_dp = dpset.EventDPReconnected(dp=self._fake_dp())
        for enter in (True, False):
            event_dp.enter = enter
            ryu_app.connect_or_disconnect_handler(event_dp)
        for event_handler in (
                ryu_app.error_handler,
                ryu_app.features_handler,
                ryu_app.packet_in_handler,
                ryu_app.desc_stats_reply_handler,
                ryu_app.port_status_handler,
                ryu_app.flowremoved_handler,
                ryu_app.reconnect_handler,
                ryu_app._datapath_connect,
                ryu_app._datapath_disconnect):
            msg = namedtuple('msg', ['datapath'])(self._fake_dp())
            event = EventOFPMsgBase(msg=msg)
            event.dp = msg.datapath
            event_handler(event)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
