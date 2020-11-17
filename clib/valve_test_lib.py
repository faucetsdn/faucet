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
import copy
import difflib
import io
import ipaddress
import logging
import os
import pstats
import shutil
import socket
import tempfile
import unittest
import yaml

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

from clib.fakeoftable import FakeOFNetwork


def build_dict(pkt):
    """
    Build and return a dictionary from a pkt
    This function is supposed to be in duality with build_pkt
    i.e. build_dict(build_pkt(dict)) == dict && build_pkt(build_dict(pkt)) == pkt
    """
    pkt_dict = {}
    arp_pkt = pkt.get_protocol(arp.arp)
    if arp_pkt:
        pkt_dict['arp_source_ip'] = arp_pkt.src_ip
        pkt_dict['arp_target_ip'] = arp_pkt.dst_ip
        pkt_dict['opcode'] = arp_pkt.opcode
    ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
    if ipv6_pkt:
        pkt_dict['ipv6_src'] = ipv6_pkt.src
        pkt_dict['ipv6_dst'] = ipv6_pkt.dst
    icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
    if icmpv6_pkt:
        type_ = icmpv6_pkt.type_
        if type_ == icmpv6.ND_ROUTER_ADVERT:
            for option in icmpv6_pkt.data.options:
                if hasattr(option, 'hw_src'):
                    pkt_dict['eth_src'] = option.hw_src
                if hasattr(option, 'prefix'):
                    pkt_dict['router_advert_ip'] = option.prefix
        elif type_ == icmpv6.ND_ROUTER_SOLICIT:
            pkt_dict['router_solicit_ip'] = None
        elif type_ == icmpv6.ND_NEIGHBOR_ADVERT:
            pkt_dict['neighbor_advert_ip'] = icmpv6_pkt.data.dst
            pkt_dict['eth_src'] = icmpv6_pkt.data.option.hw_src
        elif type_ == icmpv6.ND_NEIGHBOR_SOLICIT:
            pkt_dict['neighbor_solicit_ip'] = icmpv6_pkt.data.dst
            pkt_dict['eth_src'] = icmpv6_pkt.data.option.hw_src
        elif type_ == icmpv6.ICMPV6_ECHO_REQUEST:
            pkt_dict['echo_request_data'] = icmpv6_pkt.data.data
        else:
            raise NotImplementedError('Unknown packet type %s \n' % icmpv6_pkt)
    ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
    if ipv4_pkt:
        pkt_dict['ipv4_src'] = ipv4_pkt.src
        pkt_dict['ipv4_dst'] = ipv4_pkt.dst
    icmp_pkt = pkt.get_protocol(icmp.icmp)
    if icmp_pkt:
        type_ = icmp_pkt.type_
        if type_ == icmp.ICMP_ECHO_REQUEST:
            pkt_dict['echo_request_data'] = icmp_pkt.data.data
        else:
            raise NotImplementedError('Unknown packet type %s \n' % icmp_pkt)
    lacp_pkt = pkt.get_protocol(slow.lacp)
    if lacp_pkt:
        pkt_dict['actor_system'] = lacp_pkt.actor_system
        pkt_dict['partner_system'] = lacp_pkt.partner_system
        pkt_dict['actor_state_synchronization'] = lacp_pkt.actor_state_synchronization
    lldp_pkt = pkt.get_protocol(lldp.lldp)
    if lldp_pkt:
        def faucet_lldp_tlvs(dp_mac, tlv_type, value):
            oui = valve_packet.faucet_oui(dp_mac)
            value = str(value).encode('utf-8')
            return (oui, tlv_type, value)
        chassis_tlv = valve_packet.tlvs_by_type(lldp_pkt.tlvs, lldp.LLDP_TLV_CHASSIS_ID)[0]
        chassis_id = valve_packet.addrconv.mac.bin_to_text(chassis_tlv.chassis_id)
        pkt_dict['chassis_id'] = chassis_id
        faucet_tlvs = tuple(valve_packet.parse_faucet_lldp(lldp_pkt, chassis_id))
        remote_dp_id, remote_dp_name, remote_port_id, remote_port_state = faucet_tlvs
        pkt_dict['system_name'] = remote_dp_name
        pkt_dict['port_id'] = remote_port_id
        pkt_dict['eth_dst'] = lldp.LLDP_MAC_NEAREST_BRIDGE
        tlvs = [
            faucet_lldp_tlvs(chassis_id, valve_packet.LLDP_FAUCET_DP_ID, remote_dp_id),
            faucet_lldp_tlvs(chassis_id, valve_packet.LLDP_FAUCET_STACK_STATE, remote_port_state)
        ]
        pkt_dict['tlvs'] = tlvs
    vlan_pkt = pkt.get_protocol(vlan.vlan)
    if vlan_pkt:
        pkt_dict['vid'] = vlan_pkt.vid
    eth_pkt = pkt.get_protocol(ethernet.ethernet)
    if eth_pkt:
        pkt_dict['eth_src'] = eth_pkt.src
        if 'eth_dst' in pkt_dict and pkt_dict['eth_dst'] != eth_pkt.dst:
            raise NotImplementedError('Previous allocation of eth_dst does not match ethernet dst\n')
        pkt_dict['eth_dst'] = eth_pkt.dst
    return pkt_dict


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
        slowpath_pps: 99
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
        vid: 0x100
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
                native_vlan: v100
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
                native_vlan: v100
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
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
""" % (BASE_DP1_CONFIG, BASE_DP_CONFIG, BASE_DP_CONFIG)


class ValveTestBases:
    """Insulate test base classes from unittest so we can reuse base clases."""

    @staticmethod
    def packet_outs_from_flows(flows):
        """Return flows that are packetout actions."""
        return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPPacketOut)]

    @staticmethod
    def flowmods_from_flows(flows):
        """Return flows that are flowmods actions."""
        return [flow for flow in flows if isinstance(flow, valve_of.parser.OFPFlowMod)]

    class ValveTestNetwork(unittest.TestCase):
        """Base class for tests that require multiple DPs with their own FakeOFTables"""

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

        @staticmethod
        def create_mac_str(i, j):
            """Create a host MAC string"""
            return '00:00:00:%02x:00:%02x' % (i, j)

        @staticmethod
        def create_vid(i):
            """Create a vid with VID_PRESENT"""
            return 0x100 * i | ofp.OFPVID_PRESENT

        # Default DP name
        DP_NAME = 's1'

        # Default DP ID
        DP_ID = 1

        P1_V100_MAC = '00:00:00:01:00:01'
        P2_V100_MAC = '00:00:00:01:00:02'
        P3_V100_MAC = '00:00:00:01:00:03'
        P1_V200_MAC = '00:00:00:02:00:01'
        P2_V200_MAC = '00:00:00:02:00:02'
        P3_V200_MAC = '00:00:00:02:00:03'
        P1_V300_MAC = '00:00:00:03:00:01'
        UNKNOWN_MAC = '00:00:00:04:00:04'

        BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
        FAUCET_MAC = '0e:00:00:00:00:01'

        V100 = 0x100 | ofp.OFPVID_PRESENT
        V200 = 0x200 | ofp.OFPVID_PRESENT
        V300 = 0x300 | ofp.OFPVID_PRESENT

        # Number of tables to configure in the FakeOFTable
        NUM_TABLES = 10
        NUM_PORTS = 5

        LOGNAME = 'faucet'
        ICMP_PAYLOAD = bytes('A'*64, encoding='UTF-8')
        REQUIRE_TFM = True
        CONFIG_AUTO_REVERT = False
        CONFIG = None

        def __init__(self, *args, **kwargs):
            self.dot1x = None
            self.valves_manager = None
            self.metrics = None
            self.bgp = None
            self.logger = None

            self.registry = None
            self.notifier = None
            self.network = None
            self.last_flows_to_dp = {}

            self.tmpdir = None

            self.mock_now_sec = 100
            self.maxDiff = None

            # Used for a legacy port mechanism
            self.up_ports = {}

            super(ValveTestBases.ValveTestNetwork, self).__init__(*args, **kwargs)

        def mock_time(self, increment_sec=1):
            """
            Manage a mock timer for better unit test control
            Args:
                increment__sec (int): Amount to increment the current mock time
            Returns:
                current mock time
            """
            self.mock_now_sec += increment_sec
            return self.mock_now_sec

        def setup_valves(self, config, error_expected=0, log_stdout=False):
            """
            Set up test with config
            Args:
                config (str): The Faucet config file
                error_expected (int): The error expected, if any
                log_stdout: Whether to log to stdout or not
            """
            self.tmpdir = tempfile.mkdtemp()
            self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
            logfile = 'STDOUT' if log_stdout else os.path.join(self.tmpdir, 'faucet.log')
            self.logger = valve_util.get_logger(self.LOGNAME, logfile, logging.DEBUG, 0)
            self.registry = CollectorRegistry()
            self.metrics = faucet_metrics.FaucetMetrics(reg=self.registry)
            self.notifier = faucet_event.FaucetEventNotifier(None, self.metrics, self.logger)
            self.bgp = faucet_bgp.FaucetBgp(
                self.logger, logfile, self.metrics, self.send_flows_to_dp_by_id)
            self.dot1x = faucet_dot1x.FaucetDot1x(
                self.logger, logfile, self.metrics, self.send_flows_to_dp_by_id)
            self.valves_manager = valves_manager.ValvesManager(
                self.LOGNAME, self.logger, self.metrics, self.notifier,
                self.bgp, self.dot1x, self.CONFIG_AUTO_REVERT, self.send_flows_to_dp_by_id)
            self.last_flows_to_dp[self.DP_ID] = []
            initial_ofmsgs = self.update_config(
                config, reload_expected=False,
                error_expected=error_expected, configure_network=True)
            if not error_expected:
                for dp_id in self.valves_manager.valves:
                    self.connect_dp(dp_id)
            return initial_ofmsgs

        def teardown_valves(self):
            """Tear down test valves"""
            self.bgp.shutdown_bgp_speakers()
            valve_util.close_logger(self.logger)
            for valve in self.valves_manager.valves.values():
                valve.close_logs()
            shutil.rmtree(self.tmpdir)

        def tearDown(self):
            """Tear down the test"""
            self.teardown_valves()

        def _check_table_difference(self, before_hash, before_str, dp_id):
            """
            Checks the current table state after another check to ensure that
            the current table state is equal to the before table state.

            Args:
                before_hash (int): Hash of the table before changes
                before_str (str): String representation of the table before changes
                dp_id (int): DP ID of the table to test difference
            """
            after_hash = self.network.hash_table(int(dp_id))
            if before_hash != after_hash:
                after_str = str(self.network.tables[dp_id])
                diff = difflib.unified_diff(
                    before_str.splitlines(), after_str.splitlines())
                self.assertEqual(before_hash, after_hash,
                                 msg='%s != %s\n'.join(diff) % (before_hash, after_hash))

        def _verify_redundant_safe_offset_ofmsgs(self, ofmsgs, dp_id, offset=1):
            """
            Verify that a copy of the ofmsgs applied to the FakeOFTable with an offset
            will converge to the original table state. This ensures that a redundant
            controller with a delayed ofmsgs application will still result in
            a consistent table structure.

            Args:
                ofmsgs (list): ofmsgs to copy and apply offset to the original ofmsgs
                dp_id (int): The dp_id of the FakeOFTable to apply the ofmsgs to
                offset (int): Offset for the copied ofmsgs
            """
            if offset:
                before_hash, before_str = self.network.table_state(int(dp_id))
                offset_ofmsgs = []
                for i in range(0-offset, len(ofmsgs)):
                    if i >= 0 and i < len(ofmsgs):
                        offset_ofmsgs.append(ofmsgs[i])
                    j = i + offset
                    if j >= 0 and j < len(ofmsgs):
                        offset_ofmsgs.append(ofmsgs[j])
                self.network.apply_ofmsgs(int(dp_id), offset_ofmsgs, ignore_errors=True)
                self._check_table_difference(before_hash, before_str, dp_id)

        def apply_ofmsgs(self, ofmsgs, dp_id=None, offset=1, all_offsets=False):
            """
            Prepare and apply ofmsgs to a DP FakeOFTable

            Args:
                ofmsgs (list): Ofmsgs to prepare and then send to the FakeOFTable
                dp_id (int): The dp_id of the FakeOFTable to apply the ofmsgs to
                offset (int): offset for the duplicate flow offset check
                all_offsets (bool): If true, test all offsets for the ofmsg offset check
            """
            if not ofmsgs:
                return ofmsgs
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            before_flow_count = len(ofmsgs)
            final_ofmsgs = valve.prepare_send_flows(ofmsgs)
            after_flow_count = len(final_ofmsgs)
            reorder_ratio = before_flow_count / after_flow_count
            if before_flow_count < before_flow_count:
                self.assertGreater(
                    reorder_ratio, 0.90,
                    'inefficient duplicate flow generation (before %u, after %u)' % (
                        before_flow_count, after_flow_count))
            self.network.apply_ofmsgs(int(dp_id), final_ofmsgs)
            if all_offsets:
                for offset_iter in range(len(ofmsgs)):
                    self._verify_redundant_safe_offset_ofmsgs(ofmsgs, dp_id, offset_iter)
            elif offset:
                self._verify_redundant_safe_offset_ofmsgs(ofmsgs, dp_id, offset)
            return final_ofmsgs

        def send_flows_to_dp_by_id(self, valve, flows):
            """Callback function for ValvesManager to simulate sending flows to a DP"""
            flows = valve.prepare_send_flows(flows)
            self.last_flows_to_dp[valve.dp.dp_id] = flows

        def configure_network(self):
            """Creates the FakeOFNetwork"""
            for dp_id in self.valves_manager.valves:
                self.last_flows_to_dp[dp_id] = []
            self.network = FakeOFNetwork(self.valves_manager, self.NUM_TABLES, self.REQUIRE_TFM)

        def get_events(self):
            events = []
            while True:
                event = self.valves_manager.notifier.get_event()
                if not event:
                    return events
                events.append(event)

        def update_config(self, config, table_dpid=None, reload_type='cold',
                          reload_expected=True, error_expected=0,
                          no_reload_no_table_change=True,
                          configure_network=False):
            """
            Updates the Faucet config and reloads Faucet
            Args:
                config (str): The configuraation that will be loaded
                dp_id (int): DP ID of the expected reload type
                reload_type ('warm' or 'cold'): Expected reload increment type
                reload_expected (bool): Whether the reload type is expected to increment
                error_expected (int): The error number that is expected from the config
            """
            before_table_states = None
            if self.network is not None:
                before_table_states = {
                    dp_id: table.table_state() for dp_id, table in self.network.tables.items()}
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
            for dp_id in self.valves_manager.valves:
                self.last_flows_to_dp[dp_id] = []
            reload_ofmsgs = []
            all_ofmsgs = {}
            reload_func = partial(
                self.valves_manager.request_reload_configs,
                self.mock_time(10), self.config_file)
            if error_expected:
                reload_func()
                if configure_network:
                    self.configure_network()
            else:
                if reload_type is not None:
                    var = 'faucet_config_reload_%s_total' % reload_type
                    self.prom_inc(
                        reload_func, var=var, inc_expected=reload_expected, dp_id=table_dpid)
                else:
                    reload_func()
                if configure_network:
                    self.configure_network()
                for dp_id in self.valves_manager.valves:
                    reload_ofmsgs = self.last_flows_to_dp.get(dp_id, [])
                    # When cold starting, we must either request a disconnect from the switch or have flows to send.
                    if dp_id == self.DP_ID and before_dp_status and reload_type == 'cold' and reload_expected:
                        self.assertTrue(reload_ofmsgs is None or reload_ofmsgs, reload_ofmsgs)
                    if reload_ofmsgs is None:
                        reload_ofmsgs = self.connect_dp(dp_id)
                    else:
                        self._verify_wildcard_deletes(reload_type, reload_ofmsgs)
                        self.apply_ofmsgs(reload_ofmsgs, dp_id)
                    all_ofmsgs[dp_id] = reload_ofmsgs
                    if (not reload_expected and no_reload_no_table_change and
                            before_table_states is not None and dp_id in before_table_states):
                        before_hash, before_str = before_table_states[dp_id]
                        self._check_table_difference(before_hash, before_str, dp_id)
            self.assertEqual(before_dp_status, int(self.get_prom('dp_status')))
            self.assertEqual(error_expected, self.get_prom('faucet_config_load_error', bare=True))
            return all_ofmsgs

        def _verify_wildcard_deletes(self, reload_type, reload_ofmsgs):
            """Verify the only wildcard delete usage when warm starting, is for in_port."""
            if reload_type != 'warm':
                return
            for ofmsg in reload_ofmsgs:
                if not valve_of.is_flowdel(ofmsg):
                    continue
                self.assertNotEqual(ofmsg.table_id, valve_of.ofp.OFPTT_ALL, ofmsg)

        def update_and_revert_config(self, orig_config, new_config, reload_type,
                                     verify_func=None, before_table_states=None,
                                     table_dpid=None):
            """
            Updates to the new config then reverts back to the original config to ensure
                restarting properly dismantles/keep appropriate flow rules
            Args:
                orig_config (str): The original configuration file
                new_config (str): The new configuration file
                cold_starts (dict): Dictionary of dp_id that is expecting cold starts or warm starts
                verify_func (func): Function to verify state changes
                before_table_states (dict): Dict of string state by dp_id of the table before reloading
            """
            if before_table_states is None:
                before_table_states = {
                    dp_id: table.table_state() for dp_id, table in self.network.tables.items()}
            self.update_config(new_config, reload_type=reload_type, table_dpid=table_dpid)
            if verify_func is not None:
                verify_func()
            self.update_config(orig_config, reload_type=reload_type, table_dpid=table_dpid)
            for dp_id, states in before_table_states.items():
                before_hash, before_str = states
                self._check_table_difference(before_hash, before_str, dp_id)

        def connect_dp(self, dp_id=None):
            """
            Call to connect DP with all ports up
            Args:
                dp_id: ID for the DP that will be connected
            Returns:
                ofmsgs from connecting the DP
            """
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            discovered_up_ports = set(valve.dp.ports.keys())
            connect_msgs = (
                valve.switch_features(None) +
                valve.datapath_connect(self.mock_time(10), discovered_up_ports))
            connect_msgs = self.apply_ofmsgs(connect_msgs, dp_id)
            self.valves_manager.update_config_applied(sent={dp_id: True})
            self.assertEqual(1, int(self.get_prom('dp_status', dp_id=dp_id)))
            self.assertTrue(valve.dp.to_conf())
            return connect_msgs

        def disconnect_dp(self):
            valve = self.valves_manager.valves[self.DP_ID]
            valve.datapath_disconnect(self.mock_time())

        def migrate_stack_root(self, new_root_name):
            now = self.mock_time()
            self.valves_manager.set_stack_root(now, new_root_name)
            self.valves_manager.reload_stack_root_config(now)
            self.valves_manager.valve_flow_services(now, 'fast_state_expire')
            self.trigger_all_ports()

        def cold_start(self, dp_id=None):
            """
            Cold start a DP
            Args:
                dp_id: ID for the DP to cold start
            Returns:
                ofmsgs from re-connecting the DP
            """
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            valve.datapath_disconnect(self.mock_time())
            return self.connect_dp(dp_id)

        def get_prom(self, var, labels=None, bare=False, dp_id=None):
            """Return a Prometheus variable value."""
            if labels is None:
                labels = {}
            if not bare:
                if dp_id is None:
                    dp_id = self.DP_ID
                if dp_id not in self.valves_manager.valves:
                    dp_id = self.DP_ID
                    dp_name = self.DP_NAME
                else:
                    valve = self.valves_manager.valves[dp_id]
                    dp_name = valve.dp.name
                labels.update({
                    'dp_name': dp_name,
                    'dp_id': '0x%x' % dp_id})
            val = self.registry.get_sample_value(var, labels)
            if val is None:
                val = 0
            return val

        def prom_inc(self, func, var, labels=None, inc_expected=True, dp_id=None):
            """Check Prometheus variable increments by 1 after calling a function."""
            before = self.get_prom(var, labels, dp_id)
            func()
            after = self.get_prom(var, labels, dp_id)
            msg = '%s %s before %f after %f' % (var, labels, before, after)
            if inc_expected:
                self.assertEqual(before + 1, after, msg=msg)
            else:
                self.assertEqual(before, after, msg=msg)

        def rcv_packet(self, port, vid, match, dp_id=None):
            """
            Receives a packet by calling for the valve packet_in methods
            Args:
                port (int): The port receiving the packet
                vid (int): The VLAN receiving the packet
                match (dict): A dictionary keyed by header field names with values representing a packet
                dp_id: The DP ID of the DP receiving the packet
            Returns:
                ofmsgs from receiving the packet
            """
            if dp_id is None:
                dp_id = self.DP_ID
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
            for i in self.valves_manager.valves:
                self.last_flows_to_dp[i] = []
            now = self.mock_time(0)
            packet_in_func = partial(self.valves_manager.valve_packet_in, now, valve, msg)
            if dp_id == self.DP_ID:
                self.prom_inc(packet_in_func, 'of_packet_ins_total')
            else:
                packet_in_func()
            all_ofmsgs = {}
            for i in self.valves_manager.valves:
                rcv_packet_ofmsgs = self.last_flows_to_dp[i]
                all_ofmsgs[i] = rcv_packet_ofmsgs
                self.last_flows_to_dp[i] = []
                self.apply_ofmsgs(rcv_packet_ofmsgs, i)
            for valve_service in (
                    'resolve_gateways', 'advertise', 'fast_advertise', 'state_expire'):
                self.valves_manager.valve_flow_services(now, valve_service)
            self.valves_manager.update_metrics(now)
            return all_ofmsgs

        def rcv_lldp(self, port, other_dp, other_port, dp_id=None):
            """
            Receives an LLDP packet
            Args:
                port (Port): Port source object
                other_dp (DP): Destination DP object
                other_port (Port): Port destination object
                dp_id: The DP ID of the DP receiving the packet
            Returns:
                ofmsgs from receiving the LLDP packets
            """
            if dp_id is None:
                dp_id = self.DP_ID
            tlvs = []
            tlvs.extend(valve_packet.faucet_lldp_tlvs(other_dp))
            tlvs.extend(valve_packet.faucet_lldp_stack_state_tlvs(other_dp, other_port))
            dp_mac = other_dp.faucet_dp_mac if other_dp.faucet_dp_mac else FAUCET_MAC
            rcv_ofmsgs = self.rcv_packet(port.number, 0, {
                'eth_src': dp_mac,
                'eth_dst': lldp.LLDP_MAC_NEAREST_BRIDGE,
                'port_id': other_port.number,
                'chassis_id': dp_mac,
                'system_name': other_dp.name,
                'org_tlvs': tlvs}, dp_id=dp_id)
            return rcv_ofmsgs

        def port_labels(self, port_no, dp_id=None):
            """Get port labels"""
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            port = valve.dp.ports[port_no]
            return {'port': port.name, 'port_description': port.description}

        def port_expected_status(self, port_no, exp_status, dp_id=None):
            """
            Verify port has expected status
            Args:
                port_no (int): Port number of the port on the DP
                exp_status (int): Expected status for the port
                dp_id (int): DP ID of the DP that contains the port
            """
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            if port_no not in valve.dp.ports:
                return
            labels = self.port_labels(port_no, dp_id)
            status = int(self.get_prom('port_status', labels=labels, dp_id=dp_id))
            self.assertEqual(
                status, exp_status,
                msg='status %u != expected %u for port %s' % (
                    status, exp_status, labels))

        def get_other_valves(self, valve):
            """Return other running valves"""
            return self.valves_manager._other_running_valves(valve)  # pylint: disable=protected-access

        def set_port_down(self, port_no, dp_id=None):
            """
            Set port status of port to down
            Args:
                port_no (int): Port number to set to UP
                dp_id (int): DP ID containing the port number
            """
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            self.apply_ofmsgs(valve.port_status_handler(
                port_no, ofp.OFPPR_DELETE, ofp.OFPPS_LINK_DOWN, [], self.mock_time(0)).get(valve, []))
            self.port_expected_status(port_no, 0)

        def set_port_up(self, port_no, dp_id=None):
            """
            Set port status of port to up
            Args:
                port_no (int): Port number to set to UP
                dp_id (int): DP ID containing the port number
            """
            if dp_id is None:
                dp_id = self.DP_ID
            valve = self.valves_manager.valves[dp_id]
            self.apply_ofmsgs(valve.port_status_handler(
                port_no, ofp.OFPPR_ADD, 0, [], self.mock_time(0)).get(valve, []))
            self.port_expected_status(port_no, 1)

        def trigger_stack_ports(self, ignore_ports=None):
            """
            Trigger a stack port by receiving an LLDP packet
            Args:
                ignore_ports (list): List of port objects to ignore when sending LLDP
                    packets, this effectively takes the stack port down
            """
            # Expire all of the stack ports
            if ignore_ports:
                valves = [self.valves_manager.valves[port.dp_id] for port in ignore_ports]
                max_interval = max([valve.dp.lldp_beacon['send_interval'] for valve in valves])
                max_lost = max([port.max_lldp_lost for port in ignore_ports])
                now = self.mock_time((max_interval * max_lost) + 1)
                for dp_id in self.valves_manager.valves:
                    self.last_flows_to_dp[dp_id] = []
                self.valves_manager.valve_flow_services(now, 'fast_state_expire')
                for dp_id in self.valves_manager.valves:
                    self.apply_ofmsgs(self.last_flows_to_dp[dp_id], dp_id)
                    self.last_flows_to_dp[dp_id] = []
                for valve in self.valves_manager.valves.values():
                    for port in valve.dp.ports.values():
                        if port.stack:
                            exp_state = 4
                            self.assertEqual(
                                port.dyn_stack_current_state, exp_state,
                                '%s stack state %s != %s' % (
                                    port, port.dyn_stack_current_state, exp_state))
            # Send LLDP packets to reset the stack ports that we want to be up
            for dp_id, valve in self.valves_manager.valves.items():
                for port in valve.dp.ports.values():
                    if ignore_ports and port in ignore_ports:
                        continue
                    if port.stack:
                        peer_dp = port.stack['dp']
                        peer_port = port.stack['port']
                        self.rcv_lldp(port, peer_dp, peer_port, dp_id)
            # Verify stack ports are in the correct state
            for valve in self.valves_manager.valves.values():
                for port in valve.dp.ports.values():
                    if port.stack:
                        exp_state = 3
                        if ignore_ports and port in ignore_ports:
                            exp_state = 4
                        self.assertEqual(
                            port.dyn_stack_current_state, exp_state,
                            '%s stack state %s != %s' % (
                                port, port.dyn_stack_current_state, exp_state))

        def flap_port(self, port_no):
            """Flap op status on a port."""
            self.set_port_down(port_no)
            self.set_port_up(port_no)

        def all_stack_up(self):
            """Bring all the ports in a stack fully up"""
            for valve in self.valves_manager.valves.values():
                valve.dp.dyn_running = True
                for port in valve.dp.stack_ports():
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
                for port in valve.dp.ports.values():
                    port.dyn_phys_up = True
                for port in valve.dp.stack_ports():
                    self.up_stack_port(port, dp_id=valve.dp.dp_id)
                    self._update_port_map(port, True)
            self.trigger_all_ports(packets=packets)

        def trigger_all_ports(self, packets=10):
            """Do the needful to trigger any pending state changes"""
            valve = self.valves_manager.valves[self.DP_ID]
            interval = valve.dp.lldp_beacon['send_interval']
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
                self.apply_ofmsgs(flows, dp_id=self.DP_ID)

        def deactivate_stack_port(self, port, packets=10):
            """Deactivate a given stack port"""
            self._update_port_map(port, False)
            self.trigger_all_ports(packets=packets)

        def activate_stack_port(self, port, packets=10):
            """Deactivate a given stack port"""
            self._update_port_map(port, True)
            self.trigger_all_ports(packets=packets)

        def set_stack_port_status(self, port_no, status, valve=None):
            """Set stack port up recalculating topology as necessary."""
            if not valve:
                valve = self.valves_manager.valves[self.DP_ID]
            port = valve.dp.ports[port_no]
            port.dyn_stack_current_state = status
            valve.stack_manager.update_stack_topo(True, valve.dp, port)
            for valve_vlan in valve.dp.vlans.values():
                ofmsgs = valve.switch_manager.add_vlan(valve_vlan, cold_start=False)
                self.apply_ofmsgs(ofmsgs, dp_id=valve.dp.dp_id)

        def set_stack_port_up(self, port_no, valve=None):
            """Set stack port up recalculating topology as necessary."""
            self.set_stack_port_status(port_no, 3, valve)

        def set_stack_port_down(self, port_no, valve=None):
            """Set stack port up recalculating topology as necessary."""
            self.set_stack_port_status(port_no, 2, valve)

        def validate_flood(self, in_port, vlan_vid, out_port, expected, msg):
            bcast_match = {
                'in_port': in_port,
                'eth_dst': mac.BROADCAST_STR,
                'vlan_vid': vlan_vid,
                'eth_type': 0x800,
            }
            if expected:
                self.assertTrue(
                    self.network.tables[self.DP_ID].is_output(bcast_match, port=out_port), msg=msg)
            else:
                self.assertFalse(
                    self.network.tables[self.DP_ID].is_output(bcast_match, port=out_port), msg=msg)

        def pkt_match(self, src, dst):
            """Make a unicast packet match dict for the given src & dst"""
            return {
                'eth_src': '00:00:00:01:00:%02x' % src,
                'eth_dst': '00:00:00:01:00:%02x' % dst,
                'ipv4_src': '10.0.0.%d' % src,
                'ipv4_dst': '10.0.0.%d' % dst,
                'vid': self.V100
            }

        def _config_edge_learn_stack_root(self, new_value):
            config = yaml.load(self.CONFIG, Loader=yaml.SafeLoader)
            config['vlans']['v100']['edge_learn_stack_root'] = new_value
            return yaml.dump(config)

        def learn_hosts(self):
            """Learn some hosts."""
            # TODO: verify learn caching.
            for _ in range(2):
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.UNKNOWN_MAC,
                    'ipv4_src': '10.0.0.1',
                    'ipv4_dst': '10.0.0.4'})
                # TODO: verify host learning banned
                self.rcv_packet(1, 0x100, {
                    'eth_src': self.UNKNOWN_MAC,
                    'eth_dst': self.P1_V100_MAC,
                    'ipv4_src': '10.0.0.4',
                    'ipv4_dst': '10.0.0.1'})
                self.rcv_packet(3, 0x100, {
                    'eth_src': self.P3_V100_MAC,
                    'eth_dst': self.P2_V100_MAC,
                    'ipv4_src': '10.0.0.3',
                    'ipv4_dst': '10.0.0.2',
                    'vid': 0x100})
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
                    'ipv4_dst': '10.0.0.2',
                    'vid': 0x200})

        def verify_expiry(self):
            """Verify FIB resolution attempts expire."""
            valve = self.valves_manager.valves[self.DP_ID]

            def expire():
                now = self.mock_time(valve.dp.timeout * 2)
                state_expire = valve.state_expire(now, None)
                resolve_gws = valve.resolve_gateways(now, None)
                return state_expire, resolve_gws

            state_expire, resolve_gws = {}, {}
            # Expire resolution attempts
            for _ in range(valve.dp.max_host_fib_retry_count):
                state_expire, resolve_gws = expire()
            # If there are still more state_expire msgs, make sure they are flowdels
            state_expire, resolve_gw = expire()
            for pkts in state_expire.values():
                if pkts:
                    for pkt in pkts:
                        self.assertTrue(valve_of.is_flowdel(pkt))
            # Final check to make sure there are now absolutely no state expire msgs
            state_expire, resolve_gws = expire()
            for pkts in state_expire.values():
                self.assertFalse(pkts)

        def verify_flooding(self, matches):
            """Verify flooding for a packet, depending on the DP implementation."""
            valve = self.valves_manager.valves[self.DP_ID]

            def _verify_flood_to_port(match, port, valve_vlan, port_number=None):
                if valve_vlan.port_is_tagged(port):
                    vid = valve_vlan.vid | ofp.OFPVID_PRESENT
                else:
                    vid = 0
                if port_number is None:
                    port_number = port.number
                return self.network.tables[self.DP_ID].is_output(match, port=port_number, vid=vid)

            for match in matches:
                in_port_number = match['in_port']
                in_port = valve.dp.ports[in_port_number]

                if ('vlan_vid' in match and
                        match['vlan_vid'] & ofp.OFPVID_PRESENT != 0):
                    valve_vlan = valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
                else:
                    valve_vlan = in_port.native_vlan

                all_ports = {
                    port for port in valve.dp.ports.values() if port.running()}
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
                    if valve.floods_to_root():
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
                                msg=(
                                    '%s with unknown eth_dst not flooded'
                                    ' on VLAN %u to port %u\n%s' % (
                                        match, valve_vlan.vid,
                                        port.number, self.network.tables[self.DP_ID])))

                # Packet must not be flooded to ports not on the VLAN.
                for port in remaining_ports:
                    if port.stack:
                        self.assertTrue(
                            self.network.tables[self.DP_ID].is_output(match, port=port.number),
                            msg=('Unknown eth_dst not flooded to stack port %s' % port))
                    elif not port.mirror:
                        self.assertFalse(
                            self.network.tables[self.DP_ID].is_output(match, port=port.number),
                            msg=('Unknown eth_dst flooded to non-VLAN/stack/mirror %s' % port))

        def verify_pkt(self, pkt, expected_pkt):
            """
            Verifies that a packet contains the matches with correct values

            Args:
                pkt (packet.Packet): The packet object to build into the dictionary
                expected_pkt (dict): The expected values to be contained in the packet directory
            """
            pkt_dict = build_dict(pkt)
            for key in expected_pkt:
                self.assertTrue(
                    key in pkt_dict,
                    'key %s not in pkt %s' % (key, pkt_dict))
                if expected_pkt[key] is None:
                    # Sometimes we may not know that correct value but
                    #   want to ensure that there exists a value so use the None
                    #   value for a packet key
                    continue
                self.assertEqual(
                    expected_pkt[key], pkt_dict[key],
                    'key: %s not matching (%s != %s)' % (key, expected_pkt[key], pkt_dict[key]))

        def verify_route_add_del(self, dp_id, vlan_vid, ip_gw, ip_dst):
            """
            Verifies that adding then deleting routes maintains consistent
                flow rules in the FakeOFTable

            Args:
                dp_id (int): DP ID of the DP receiving the route
                vlan_vid (Vlan): VLAN VID belonging to the route
                ip_gw (ipaddress.IPv(4/6)Address): IP route gateway
                ip_dst (ipaddress.IPv(4/6)Network): IP route destination
            """
            valve = self.valves_manager.valves[dp_id]
            valve_vlan = valve.dp.vlans[vlan_vid]
            before_table_state = str(self.network.tables[dp_id])
            route_add_replies = valve.add_route(valve_vlan, ip_gw, ip_dst)
            self.assertTrue(route_add_replies)
            self.apply_ofmsgs(route_add_replies, dp_id)
            route_del_replies = valve.del_route(valve_vlan, ip_dst)
            self.assertTrue(route_del_replies)
            self.apply_ofmsgs(route_del_replies, dp_id)
            after_table_state = str(self.network.tables[dp_id])
            diff = difflib.unified_diff(
                before_table_state.splitlines(), after_table_state.splitlines())
            self.assertEqual(
                before_table_state, after_table_state, msg='\n'.join(diff))


    class ValveTestBig(ValveTestNetwork):
        """Test basic switching/L2/L3 functions."""

        def setUp(self):
            self.CONFIG = CONFIG
            self.setup_valves(CONFIG)

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
            valve = self.valves_manager.valves[self.DP_ID]
            self.assertEqual(1, int(self.get_prom('dp_status')))
            self.prom_inc(partial(valve.datapath_disconnect, self.mock_time()), 'of_dp_disconnections_total')
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
            valve = self.valves_manager.valves[self.DP_ID]
            datapath = None
            msg = valve_of.parser.OFPFlowMod(datapath=datapath)
            msg.xid = 123
            valve.recent_ofmsgs.append(msg)
            test_error = valve_of.parser.OFPErrorMsg(datapath=datapath, msg=msg)
            valve.oferror(test_error)

        def test_tfm(self):
            """Test TFM is sent."""
            valve = self.valves_manager.valves[self.DP_ID]
            network_table = self.network.tables[self.DP_ID]
            self.assertTrue(
                isinstance(valve, TfmValve),
                msg=type(valve))
            discovered_up_ports = set(range(1, self.NUM_PORTS + 1))
            flows = valve.datapath_connect(self.mock_time(10), discovered_up_ports)
            self.apply_ofmsgs(flows)
            tfm_flows = [
                flow for flow in flows if isinstance(
                    flow, valve_of.parser.OFPTableFeaturesStatsRequest)]
            self.assertTrue(tfm_flows)
            for table_name, table in valve.dp.tables.items():
                # Ensure the TFM generated for each table has the correct values
                table_id = table.table_id
                self.assertIn(table_id, network_table.tfm)
                tfm_body = network_table.tfm[table_id]
                tfm_oxm = [
                    tfm for tfm in tfm_body.properties
                    if isinstance(tfm, valve_of.parser.OFPTableFeaturePropOxm)]
                tfm_setfields = []
                tfm_matchtypes = []
                tfm_exactmatch = []
                for oxm in tfm_oxm:
                    if oxm.type == valve_of.ofp.OFPTFPT_MATCH:
                        tfm_matchtypes.extend(oxm.oxm_ids)
                    elif oxm.type == valve_of.ofp.OFPTFPT_WILDCARDS:
                        tfm_exactmatch.extend(oxm.oxm_ids)
                    elif oxm.type == valve_of.ofp.OFPTFPT_APPLY_SETFIELD:
                        tfm_setfields.extend(oxm.oxm_ids)
                for oxm_id in tfm_matchtypes:
                    self.assertIn(oxm_id.type, table.match_types)
                    self.assertEqual(oxm_id.hasmask, table.match_types[oxm_id.type])
                for oxm_id in tfm_exactmatch:
                    self.assertIn(oxm_id.type, table.match_types)
                    self.assertEqual(oxm_id.hasmask, table.match_types[oxm_id.type])
                for oxm_id in tfm_setfields:
                    self.assertIn(oxm_id.type, table.set_fields)
                    self.assertFalse(oxm_id.hasmask)
                tfm_nexttables = [
                    tfm for tfm in tfm_body.properties
                    if isinstance(tfm, valve_of.parser.OFPTableFeaturePropNextTables)]
                tfm_nexttable = []
                tfm_misstable = []
                for tfm_nt in tfm_nexttables:
                    if tfm_nt.type == valve_of.ofp.OFPTFPT_NEXT_TABLES:
                        tfm_nexttable.append(tfm_nt)
                    elif tfm_nt.type == valve_of.ofp.OFPTFPT_NEXT_TABLES_MISS:
                        tfm_misstable.append(tfm_nt)
                if table.next_tables:
                    self.assertEqual(len(tfm_nexttable), 1)
                    self.assertEqual(tfm_nexttable[0].table_ids, table.next_tables)
                if table.table_config.miss_goto:
                    self.assertEqual(len(tfm_misstable), 1)
                    miss_id = valve.dp.tables[table.table_config.miss_goto].table_id
                    self.assertEqual(tfm_misstable[0].table_ids, [miss_id])

        def test_pkt_meta(self):
            """Test bad fields in OFPacketIn."""
            valve = self.valves_manager.valves[self.DP_ID]
            msg = parser.OFPPacketIn(datapath=None)
            self.assertEqual(None, valve.parse_pkt_meta(msg))
            msg.cookie = valve.dp.cookie
            self.assertEqual(None, valve.parse_pkt_meta(msg))
            msg.reason = valve_of.ofp.OFPR_ACTION
            self.assertEqual(None, valve.parse_pkt_meta(msg))
            msg.match = parser.OFPMatch(in_port=1)
            self.assertEqual(None, valve.parse_pkt_meta(msg))
            msg.data = b'1234'
            self.assertEqual(None, valve.parse_pkt_meta(msg))

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
                'port_id': 1})[self.DP_ID])

        def test_bogon_arp_for_controller(self):
            """Bogon ARP request for controller VIP."""
            replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
                'arp_code': arp.ARP_REQUEST,
                'arp_source_ip': '8.8.8.8',
                'arp_target_ip': '10.0.0.254'})[self.DP_ID]
            # Must be no ARP reply to an ARP request not in our subnet.
            self.assertFalse(ValveTestBases.packet_outs_from_flows(replies))

        def test_arp_for_controller(self):
            """ARP request for controller VIP."""
            valve = self.valves_manager.valves[self.DP_ID]
            for _retries in range(3):
                for arp_mac in (mac.BROADCAST_STR, valve.dp.vlans[0x100].faucet_mac):
                    arp_replies = self.rcv_packet(1, 0x100, {
                        'eth_src': self.P1_V100_MAC,
                        'eth_dst': arp_mac,
                        'arp_code': arp.ARP_REQUEST,
                        'arp_source_ip': '10.0.0.1',
                        'arp_target_ip': '10.0.0.254'})[self.DP_ID]
                    packet_outs = ValveTestBases.packet_outs_from_flows(arp_replies)
                    self.assertTrue(packet_outs)
                    for arp_pktout in packet_outs:
                        pkt = packet.Packet(arp_pktout.data)
                        exp_pkt = {
                            'opcode': 2,
                            'arp_source_ip': '10.0.0.254',
                            'arp_target_ip': '10.0.0.1',
                            'eth_src': FAUCET_MAC,
                            'eth_dst': self.P1_V100_MAC}
                        self.verify_pkt(pkt, exp_pkt)

        def test_arp_reply_from_host(self):
            """ARP reply for host."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'arp_code': arp.ARP_REPLY,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})[self.DP_ID]
            self.assertTrue(arp_replies)
            self.assertFalse(ValveTestBases.packet_outs_from_flows(arp_replies))

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
                        'neighbor_solicit_ip': str(dst_ip)})[self.DP_ID]
                    packet_outs = ValveTestBases.packet_outs_from_flows(nd_replies)
                    self.assertTrue(packet_outs)
                    for nd_pktout in packet_outs:
                        pkt = packet.Packet(nd_pktout.data)
                        exp_pkt = {
                            'eth_src': FAUCET_MAC,
                            'eth_dst': self.P2_V200_MAC,
                            'ipv6_src': str(dst_ip),
                            'ipv6_dst': 'fc00::1:1',
                            'neighbor_advert_ip': str(dst_ip)}
                        self.verify_pkt(pkt, exp_pkt)

        def test_nd_from_host(self):
            """IPv6 NA from host."""
            na_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:1',
                'ipv6_dst': 'fc00::1:254',
                'neighbor_advert_ip': 'fc00::1:1'})[self.DP_ID]
            self.assertTrue(na_replies)
            self.assertFalse(ValveTestBases.packet_outs_from_flows(na_replies))

        def test_ra_for_controller(self):
            """IPv6 RA for controller."""
            router_solicit_ip = 'ff02::2'
            ra_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': '33:33:00:00:00:02',
                'vid': 0x200,
                'ipv6_src': 'fe80::1:1',
                'ipv6_dst': router_solicit_ip,
                'router_solicit_ip': router_solicit_ip})[self.DP_ID]
            packet_outs = ValveTestBases.packet_outs_from_flows(ra_replies)
            self.assertTrue(packet_outs)
            for ra_pktout in packet_outs:
                pkt = packet.Packet(ra_pktout.data)
                exp_pkt = {
                    'ipv6_src': 'fe80::1:254',
                    'ipv6_dst': 'fe80::1:1',
                    'eth_src': FAUCET_MAC,
                    'eth_dst': self.P2_V200_MAC,
                    'router_advert_ip': 'fc00::1:0'}
                self.verify_pkt(pkt, exp_pkt)

        def test_icmp_ping_controller(self):
            """IPv4 ping controller VIP."""
            echo_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.254',
                'echo_request_data': self.ICMP_PAYLOAD})[self.DP_ID]
            packet_outs = ValveTestBases.packet_outs_from_flows(echo_replies)
            self.assertTrue(packet_outs)
            data = packet_outs[0].data
            self.assertTrue(data.endswith(self.ICMP_PAYLOAD), msg=data)

        def test_unresolved_route(self):
            """Test unresolved route tries to resolve."""
            ip_dst = ipaddress.IPv4Network('10.100.100.0/24')
            ip_gw = ipaddress.IPv4Address('10.0.0.1')
            valve = self.valves_manager.valves[self.DP_ID]
            valve_vlan = valve.dp.vlans[0x100]
            route_add_replies = valve.add_route(
                valve_vlan, ip_gw, ip_dst)
            self.assertFalse(route_add_replies)
            resolve_replies = valve.resolve_gateways(
                self.mock_time(10), None)
            self.assertFalse(resolve_replies)
            resolve_replies = valve.resolve_gateways(
                self.mock_time(99), None)
            self.assertTrue(resolve_replies)

        def test_add_del_route(self):
            """IPv4 add/del of a route."""
            arp_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': mac.BROADCAST_STR,
                'arp_code': arp.ARP_REQUEST,
                'arp_source_ip': '10.0.0.1',
                'arp_target_ip': '10.0.0.254'})[self.DP_ID]
            pkt_outs = ValveTestBases.packet_outs_from_flows(arp_replies)
            self.assertTrue(pkt_outs)
            for arp_pktout in pkt_outs:
                pkt = packet.Packet(arp_pktout.data)
                exp_pkt = {
                    'arp_source_ip': '10.0.0.254',
                    'arp_target_ip': '10.0.0.1',
                    'eth_src': FAUCET_MAC,
                    'eth_dst': self.P1_V100_MAC}
                self.verify_pkt(pkt, exp_pkt)
            ip_gw = ipaddress.IPv4Address('10.0.0.1')
            ip_dst = ipaddress.IPv4Network('10.100.100.0/24')
            self.verify_route_add_del(self.DP_ID, 0x100, ip_gw, ip_dst)

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
            fib_route_replies = fib_route_replies[self.DP_ID]
            self.assertTrue(fib_route_replies)
            self.assertFalse(ValveTestBases.packet_outs_from_flows(fib_route_replies))
            valve = self.valves_manager.valves[self.DP_ID]
            route_add_replies = valve.add_route(
                valve.dp.vlans[0x100],
                ipaddress.IPv4Address('10.0.0.2'),
                ipaddress.IPv4Network('0.0.0.0/0'))
            self.assertTrue(route_add_replies)
            self.verify_expiry()

        def test_host_ipv6_fib_route(self):
            """Test learning a FIB rule for an IPv6 host."""
            fib_route_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:2',
                'ipv6_dst': 'fc00::1:4',
                'echo_request_data': self.ICMP_PAYLOAD})[self.DP_ID]
            # We want to know this host was learned we did not get packet outs.
            self.assertTrue(fib_route_replies)
            self.assertFalse(ValveTestBases.packet_outs_from_flows(fib_route_replies))
            self.verify_expiry()

        def test_ping_unknown_neighbor(self):
            """IPv4 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(1, 0x100, {
                'eth_src': self.P1_V100_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x100,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.99',
                'echo_request_data': self.ICMP_PAYLOAD})[self.DP_ID]
            self.assertTrue(echo_replies)
            out_pkts = ValveTestBases.packet_outs_from_flows(echo_replies)
            self.assertTrue(out_pkts)
            for out_pkt in out_pkts:
                pkt = packet.Packet(out_pkt.data)
                exp_pkt = {
                    'arp_source_ip': '10.0.0.254',
                    'arp_target_ip': '10.0.0.99',
                    'opcode': 1,
                    'eth_src': FAUCET_MAC,
                    'eth_dst': self.BROADCAST_MAC
                }
                self.verify_pkt(pkt, exp_pkt)

        def test_ping6_unknown_neighbor(self):
            """IPv6 ping unknown host on same subnet, causing proactive learning."""
            echo_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:2',
                'ipv6_dst': 'fc00::1:4',
                'echo_request_data': self.ICMP_PAYLOAD})[self.DP_ID]
            self.assertTrue(echo_replies)
            out_pkts = ValveTestBases.packet_outs_from_flows(echo_replies)
            self.assertTrue(out_pkts)
            for out_pkt in out_pkts:
                pkt = packet.Packet(out_pkt.data)
                exp_pkt = {
                    'ipv6_src': 'fc00::1:254',
                    'ipv6_dst': 'ff02::1:ff01:4',
                    'neighbor_solicit_ip': 'fc00::1:4',
                    'eth_src': FAUCET_MAC,
                    'eth_dst': '33:33:ff:01:00:04'
                }
                self.verify_pkt(pkt, exp_pkt)

        def test_icmpv6_ping_controller(self):
            """IPv6 ping controller VIP."""
            echo_replies = self.rcv_packet(2, 0x200, {
                'eth_src': self.P2_V200_MAC,
                'eth_dst': FAUCET_MAC,
                'vid': 0x200,
                'ipv6_src': 'fc00::1:1',
                'ipv6_dst': 'fc00::1:254',
                'echo_request_data': self.ICMP_PAYLOAD})[self.DP_ID]
            packet_outs = ValveTestBases.packet_outs_from_flows(echo_replies)
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
                    self.network.tables[self.DP_ID].is_output(match),
                    msg='Packets with incorrect vlan tags are output')

        def test_unknown_eth_src(self):
            """Test that packets from unknown macs are sent to controller.

            Untagged packets should have VLAN tags pushed before they are sent to
            the controller.
            """
            valve = self.valves_manager.valves[self.DP_ID]
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
                    vid = valve.dp.get_native_vlan(match['in_port']).vid
                    vid = vid | ofp.OFPVID_PRESENT
                self.assertTrue(
                    self.network.tables[self.DP_ID].is_output(match, ofp.OFPP_CONTROLLER, vid=vid),
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
                    self.network.tables[self.DP_ID].is_output(match, port=ofp.OFPP_CONTROLLER),
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
                self.network.tables[self.DP_ID].is_output(match, port=ofp.OFPP_CONTROLLER),
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
                    self.network.tables[self.DP_ID].is_output(
                        match, result['out_port'], vid=result['vlan_vid']),
                    msg='packet not output to port correctly when eth dst is known')
                incorrect_ports = set(range(1, self.NUM_PORTS + 1))
                incorrect_ports.remove(result['out_port'])
                for port in incorrect_ports:
                    self.assertFalse(
                        self.network.tables[self.DP_ID].is_output(match, port=port),
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
                self.network.tables[self.DP_ID].is_output(match1, ofp.OFPP_CONTROLLER),
                msg=('mac address being seen on a vlan affects eth_src rule on '
                     'other vlan'))

            # check eth_dst rule
            match2 = {'in_port': 3, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(match2, port=1, vid=0),
                msg=('mac address being seen on a vlan affects eth_dst rule on '
                     'other vlan'))
            for port in (2, 4):
                self.assertFalse(
                    self.network.tables[self.DP_ID].is_output(match2, port=port),
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
                self.network.tables[self.DP_ID].is_output(match, port=2, vid=self.V100),
                msg='Packet not output correctly after mac is learnt on new port')
            self.assertFalse(
                self.network.tables[self.DP_ID].is_output(match, port=1),
                msg='Packet output on old port after mac is learnt on new port')

        def test_port_delete_eth_dst(self):
            """Test that when a port is disabled packets are correctly output. """
            valve = self.valves_manager.valves[self.DP_ID]
            match = {'in_port': 2, 'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}

            valve_vlan = valve.dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            ofmsgs = valve.port_delete(port_num=1)
            self.apply_ofmsgs(ofmsgs)

            # Check packets are output to each port on vlan
            for port in valve_vlan.get_ports():
                if port.number != match['in_port'] and port.running():
                    if valve_vlan.port_is_tagged(port):
                        vid = valve_vlan.vid | ofp.OFPVID_PRESENT
                    else:
                        vid = 0
                    self.assertTrue(
                        self.network.tables[self.DP_ID].is_output(match, port=port.number, vid=vid),
                        msg=('packet %s with eth dst learnt on deleted port not output '
                             'correctly on vlan %u to port %u' % (
                                 match, valve_vlan.vid, port.number)))

        def test_port_down_eth_src_removal(self):
            """Test that when a port goes down and comes back up learnt mac
            addresses are deleted."""

            match = {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC}
            self.flap_port(1)
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(match, port=ofp.OFPP_CONTROLLER),
                msg='Packet not output to controller after port bounce')

        def test_port_add_input(self):
            """Test that when a port is enabled packets are input correctly."""
            valve = self.valves_manager.valves[self.DP_ID]

            match = {'in_port': 1, 'vlan_vid': 0}
            orig_config = yaml.load(self.CONFIG, Loader=yaml.SafeLoader)
            deletedport1_config = copy.copy(orig_config)
            del deletedport1_config['dps'][self.DP_NAME]['interfaces']['p1']
            self.update_config(yaml.dump(deletedport1_config))
            self.assertFalse(
                self.network.tables[self.DP_ID].is_output(match, port=2, vid=self.V100),
                msg='Packet output after port delete')

            self.update_config(self.CONFIG)
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(match, port=2, vid=self.V100),
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
                self.network.tables[self.DP_ID].is_output(drop_match),
                msg='packet not blocked by ACL')
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(accept_match, port=3, vid=self.V200),
                msg='packet not allowed by ACL')

        def test_dp_acl_deny_ordered(self):
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
                    - set_fields:
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
                self.network.tables[self.DP_ID].is_output(drop_match),
                msg='packet not blocked by ACL')
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(accept_match, port=3, vid=self.V200),
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
                    self.network.tables[self.DP_ID].is_output(match, port=3, vid=self.V200),
                    msg='Packet not output before adding ACL')

            self.update_config(acl_config)
            self.assertFalse(
                self.network.tables[self.DP_ID].is_output(drop_match),
                msg='packet not blocked by ACL')
            self.assertTrue(
                self.network.tables[self.DP_ID].is_output(accept_match, port=3, vid=self.V200),
                msg='packet not allowed by ACL')

        def test_lldp_beacon(self):
            """Test LLDP beacon service."""
            valve = self.valves_manager.valves[self.DP_ID]
            lldp_pkts = valve.fast_advertise(self.mock_time(10), None)
            self.assertTrue(lldp_pkts)
            out_pkts = ValveTestBases.packet_outs_from_flows(lldp_pkts[valve])
            self.assertTrue(out_pkts)
            for out_pkt in out_pkts:
                pkt = packet.Packet(out_pkt.data)
                exp_pkt = {
                    'chassis_id': FAUCET_MAC,
                    'system_name': 'faucet',
                    'port_id': None,
                    'eth_src': FAUCET_MAC,
                    'eth_dst': lldp.LLDP_MAC_NEAREST_BRIDGE,
                    'tlvs': None
                }
                self.verify_pkt(pkt, exp_pkt)

        def test_unknown_port(self):
            """Test port status change for unknown port handled."""
            self.set_port_up(99)

        def test_port_modify(self):
            """Set port status modify."""
            valve = self.valves_manager.valves[self.DP_ID]
            for port_status in (0, 1):
                self.apply_ofmsgs(valve.port_status_handler(
                    1, ofp.OFPPR_MODIFY, port_status, [], self.mock_time())[valve])

        def test_unknown_port_status(self):
            """Test unknown port status message."""
            valve = self.valves_manager.valves[self.DP_ID]
            known_messages = set([ofp.OFPPR_MODIFY, ofp.OFPPR_ADD, ofp.OFPPR_DELETE])
            unknown_messages = list(set(range(0, len(known_messages) + 1)) - known_messages)
            self.assertTrue(unknown_messages)
            self.assertFalse(valve.port_status_handler(
                1, unknown_messages[0], 1, [], self.mock_time()).get(valve, []))

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
            valve = self.valves_manager.valves[self.DP_ID]
            now = self.mock_time(10)
            for _ in range(valve.dp.ignore_learn_ins * 2 + 1):
                if valve.rate_limit_packet_ins(now):
                    return
            self.fail('packet in rate limit not triggered')

        def test_ofdescstats_handler(self):
            """Test OFDescStatsReply handler."""
            valve = self.valves_manager.valves[self.DP_ID]
            body = parser.OFPDescStats(
                mfr_desc=u'test_mfr_desc'.encode(),
                hw_desc=u'test_hw_desc'.encode(),
                sw_desc=u'test_sw_desc'.encode(),
                serial_num=u'99'.encode(),
                dp_desc=u'test_dp_desc'.encode())
            valve.ofdescstats_handler(body)
            invalid_body = parser.OFPDescStats(
                mfr_desc=b'\x80',
                hw_desc=b'test_hw_desc',
                sw_desc=b'test_sw_desc',
                serial_num=b'99',
                dp_desc=b'test_dp_desc')
            valve.ofdescstats_handler(invalid_body)

        def test_dp_disconnect_cleanup(self):
            """Test port varz cleanup post dp disconnect"""
            valve = self.valves_manager.valves[self.DP_ID]
            port_num = list(valve.dp.ports.keys())[0]
            self.port_expected_status(port_num, 1)
            self.disconnect_dp()
            self.port_expected_status(port_num, 0)


    class ValveTestStackedRouting(ValveTestNetwork):
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
                4:
                    stack: {dp: s5, port: 4}
        s2:
            dp_id: 2
            hardware: 'GenericTFM'
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
            hardware: 'GenericTFM'
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
            hardware: 'GenericTFM'
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s3, port: 4}
                4:
                    stack: {dp: s5, port: 3}
        s5:
            dp_id: 5
            hardware: 'GenericTFM'
            interfaces:
                1:
                    native_vlan: vlan100
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s4, port: 4}
                4:
                    stack: {dp: s1, port: 4}
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
            self.setup_valves(self.CONFIG)
            self.trigger_stack_ports()

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
                    expected_port = valve.stack_manager.relative_port_towards(host_valve.dp.name)
                    self.assertEqual(expected_port, nexthop.port)

        def test_router_cache_learn_hosts(self):
            """Have all router caches contain proper host nexthops"""
            # Learn Vlan100 hosts
            for host_id in self.V100_HOSTS:
                dp_id = host_id
                self.rcv_packet(1, self.V100, self.create_match(
                    1, host_id, self.VLAN100_FAUCET_MAC,
                    self.VLAN100_FAUCET_VIPS, arp.ARP_REPLY), dp_id=dp_id)
                self.verify_router_cache(
                    self.create_ip(1, host_id), self.create_mac(1, host_id), self.V100, dp_id)
            # Learn Vlan200 hosts
            for host_id in self.V200_HOSTS:
                dp_id = host_id
                self.rcv_packet(2, self.V200, self.create_match(
                    2, host_id, self.VLAN200_FAUCET_MAC,
                    self.VLAN200_FAUCET_VIPS, arp.ARP_REPLY), dp_id=dp_id)
                self.verify_router_cache(
                    self.create_ip(2, host_id), self.create_mac(2, host_id), self.V200, dp_id)
