#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve.py."""

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


import copy
import unittest

from ryu.lib import mac
from ryu.lib.packet import slow
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from faucet import valve_of
from faucet import valve_packet

from clib.valve_test_lib import (
    CONFIG, DP1_CONFIG, FAUCET_MAC, GROUP_DP1_CONFIG, IDLE_DP1_CONFIG,
    ValveTestBases)

from clib.fakeoftable import CONTROLLER_PORT


class ValveTestCase(ValveTestBases.ValveTestBig):
    """Run complete set of basic tests."""


class ValveFuzzTestCase(ValveTestBases.ValveTestNetwork):
    """Test unknown ports/VLANs."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_fuzz_vlan(self):
        """Test unknown VIDs/ports."""
        for _ in range(0, 3):
            for i in range(0, 64):
                self.rcv_packet(1, i, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.P2_V200_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.3',
                    'vid': i})
            for i in range(0, 64):
                self.rcv_packet(i, 0x100, {
                    'eth_src': self.P1_V100_MAC,
                    'eth_dst': self.P2_V200_MAC,
                    'ipv4_src': '10.0.0.2',
                    'ipv4_dst': '10.0.0.3',
                    'vid': 0x100})
        # pylint: disable=no-member
        # pylint: disable=no-value-for-parameter
        cache_info = valve_packet.parse_packet_in_pkt.cache_info()
        self.assertGreater(cache_info.hits, cache_info.misses, msg=cache_info)


class ValveCoprocessorTestCase(ValveTestBases.ValveTestNetwork):
    """Test direct packet output using coprocessor."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                coprocessor: {strategy: vlan_vid, vlan_vid_base: 0x200}
            p2:
                number: 2
                native_vlan: testvlan
            p3:
                number: 3
                native_vlan: testvlan
vlans:
    testvlan:
        vid: 0x100
        acls_in: [bypassedbycoprocessor]
acls:
    bypassedbycoprocessor:
        - rule:
            ipv4_src: 10.0.0.99
            dl_type: 0x0800
            actions:
                allow: 0
        - rule:
            actions:
                allow: 1
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_output(self):
        # VID for direct output to port 2
        copro_vid_out = (0x200 + 2) | ofp.OFPVID_PRESENT
        direct_match = {
            'in_port': 1, 'vlan_vid': copro_vid_out, 'eth_type': ether.ETH_TYPE_IP,
            'eth_src': self.P1_V100_MAC, 'eth_dst': mac.BROADCAST_STR}
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(direct_match, port=2))
        p2_host_match = {
            'eth_src': self.P1_V100_MAC, 'eth_dst': self.P2_V200_MAC,
            'ipv4_src': '10.0.0.2', 'ipv4_dst': '10.0.0.3',
            'eth_type': ether.ETH_TYPE_IP}
        p2_host_receive = copy.deepcopy(p2_host_match)
        p2_host_receive.update({'in_port': 2})
        # learn P2 host
        self.rcv_packet(2, 0x100, p2_host_receive)
        # copro can send to P2 via regular pipeline and is not subject to VLAN ACL.
        p2_copro_host_receive = copy.deepcopy(p2_host_match)
        p2_copro_host_receive.update(
            {'in_port': 1,
             'ipv4_src': '10.0.0.99', 'ipv4_dst': '10.0.0.3',
             'eth_src': p2_host_match['eth_dst'],
             'eth_dst': p2_host_match['eth_src']})
        p2_copro_host_receive['vlan_vid'] = 0x100 | ofp.OFPVID_PRESENT
        self.assertTrue(table.is_output(p2_copro_host_receive, port=2, vid=0x100))
        # copro send to P2 was not flooded
        self.assertFalse(table.is_output(p2_copro_host_receive, port=3, vid=0x100))


class ValveRestBcastTestCase(ValveTestBases.ValveTestNetwork):

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                restricted_bcast_arpnd: true
            p2:
                number: 2
                native_vlan: 0x100
            p3:
                number: 3
                native_vlan: 0x100
                restricted_bcast_arpnd: true
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_rest_bcast(self):
        match = {
            'in_port': 1, 'vlan_vid': 0, 'eth_type': ether.ETH_TYPE_IP,
            'eth_src': self.P1_V100_MAC, 'eth_dst': mac.BROADCAST_STR}
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=3))
        match = {
            'in_port': 2, 'vlan_vid': 0, 'eth_type': ether.ETH_TYPE_IP,
            'eth_src': self.P1_V100_MAC, 'eth_dst': mac.BROADCAST_STR}
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=3))


class ValveOFErrorTestCase(ValveTestBases.ValveTestNetwork):
    """Test decoding of OFErrors."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_oferror_parser(self):
        """Test OF error parser works"""
        for type_code, error_tuple in valve_of.OFERROR_TYPE_CODE.items():
            self.assertTrue(isinstance(type_code, int))
            type_str, error_codes = error_tuple
            self.assertTrue(isinstance(type_str, str))
            for error_code, error_str in error_codes.items():
                self.assertTrue(isinstance(error_code, int))
                self.assertTrue(isinstance(error_str, str))
        test_err = parser.OFPErrorMsg(
            datapath=None, type_=ofp.OFPET_FLOW_MOD_FAILED, code=ofp.OFPFMFC_UNKNOWN)
        valve = self.valves_manager.valves[self.DP_ID]
        valve.oferror(test_err)
        test_unknown_type_err = parser.OFPErrorMsg(
            datapath=None, type_=666, code=ofp.OFPFMFC_UNKNOWN)
        valve.oferror(test_unknown_type_err)
        test_unknown_code_err = parser.OFPErrorMsg(
            datapath=None, type_=ofp.OFPET_FLOW_MOD_FAILED, code=666)
        valve.oferror(test_unknown_code_err)


class ValveGroupTestCase(ValveTestBases.ValveTestNetwork):
    """Tests for datapath with group support."""

    CONFIG = """
dps:
    s1:
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
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
""" % GROUP_DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

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


class ValveIdleLearnTestCase(ValveTestBases.ValveTestNetwork):
    """Smoke test for idle-flow based learning. This feature is not currently reliable."""

    CONFIG = """
dps:
    s1:
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
        self.setup_valves(self.CONFIG)

    def test_known_eth_src_rule(self):
        """Test removal flow handlers."""
        self.learn_hosts()
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertTrue(
            valve.flow_timeout(
                self.mock_time(),
                valve.dp.tables['eth_dst'].table_id,
                {'vlan_vid': self.V100, 'eth_dst': self.P1_V100_MAC}))
        self.assertFalse(
            valve.flow_timeout(
                self.mock_time(),
                valve.dp.tables['eth_src'].table_id,
                {'vlan_vid': self.V100, 'in_port': 1, 'eth_src': self.P1_V100_MAC}))

    def test_host_learn_coldstart(self):
        """Test flow learning, including cold-start cache invalidation"""
        valve = self.valves_manager.valves[self.DP_ID]
        match = {
            'in_port': 3, 'vlan_vid': self.V100, 'eth_type': ether.ETH_TYPE_IP,
            'eth_src': self.P3_V100_MAC, 'eth_dst': self.P1_V100_MAC}
        table = self.network.tables[self.DP_ID]
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=2))
        self.assertTrue(table.is_output(match, port=CONTROLLER_PORT))
        self.learn_hosts()
        self.assertTrue(table.is_output(match, port=1))
        self.assertFalse(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=CONTROLLER_PORT))
        self.cold_start()
        self.assertTrue(table.is_output(match, port=1))
        self.assertTrue(table.is_output(match, port=2))
        self.assertTrue(table.is_output(match, port=CONTROLLER_PORT))
        self.mock_time(valve.dp.timeout // 4 * 3)
        self.learn_hosts()
        self.assertTrue(table.is_output(match, port=1))
        self.assertFalse(table.is_output(match, port=2))
        self.assertFalse(table.is_output(match, port=CONTROLLER_PORT))


class ValveLACPTestCase(ValveTestBases.ValveTestNetwork):
    """Test LACP."""

    CONFIG = """
dps:
    s1:
%s
        lacp_timeout: 5
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
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        valve = self.valves_manager.valves[self.DP_ID]
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertFalse(
            valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            3, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertTrue(
            valve.dp.ports[1].non_stack_forwarding())
        self.learn_hosts()
        self.verify_expiry()

    def test_lacp_flap(self):
        """Test LACP handles state 0->1->0."""
        valve = self.valves_manager.valves[self.DP_ID]
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertFalse(
            valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            3, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertTrue(
            valve.dp.ports[1].non_stack_forwarding())
        self.learn_hosts()
        self.verify_expiry()
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 0})
        self.assertEqual(
            5, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertFalse(
            valve.dp.ports[1].non_stack_forwarding())

    def test_lacp_timeout(self):
        """Test LACP comes up and then times out."""
        valve = self.valves_manager.valves[self.DP_ID]
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertFalse(
            valve.dp.ports[1].non_stack_forwarding())
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            3, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertTrue(
            valve.dp.ports[1].non_stack_forwarding())
        future_now = self.mock_time(10)
        expire_ofmsgs = valve.state_expire(future_now, None)
        self.assertTrue(expire_ofmsgs)
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        self.assertFalse(
            valve.dp.ports[1].non_stack_forwarding())

    def test_dp_disconnect(self):
        """Test LACP state when disconnects."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            3, int(self.get_prom('port_lacp_state', labels=labels)))
        self.disconnect_dp()
        self.assertEqual(
            0, int(self.get_prom('port_lacp_state', labels=labels)))


class ValveTFMSizeOverride(ValveTestBases.ValveTestNetwork):
    """Test TFM size override."""

    CONFIG = """
dps:
    s1:
%s
        table_sizes:
            eth_src: 999
        interfaces:
            p1:
                number: 1
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_size(self):
        table = self.network.tables[self.DP_ID]
        tfm_by_name = {body.name: body for body in table.tfm.values()}
        eth_src_table = tfm_by_name.get(b'eth_src', None)
        self.assertTrue(eth_src_table)
        if eth_src_table is not None:
            self.assertEqual(999, eth_src_table.max_entries)


class ValveTFMSize(ValveTestBases.ValveTestNetwork):
    """Test TFM sizer."""

    NUM_PORTS = 128

    CONFIG = """
dps:
    s1:
%s
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
                lacp_active: True
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
        interface_ranges:
            6-128:
                native_vlan: v100
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
    v300:
        vid: 0x300
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)

    def test_size(self):
        table = self.network.tables[self.DP_ID]
        tfm_by_name = {body.name: body for body in table.tfm.values()}
        flood_table = tfm_by_name.get(b'flood', None)
        self.assertTrue(flood_table)
        if flood_table is not None:
            self.assertGreater(flood_table.max_entries, self.NUM_PORTS * 2)


class ValveActiveLACPTestCase(ValveTestBases.ValveTestNetwork):
    """Test LACP."""

    CONFIG = """
dps:
    s1:
%s
        lacp_timeout: 5
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                lacp: 1
                lacp_active: True
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
        self.setup_valves(self.CONFIG)
        self.activate_all_ports()

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            1, int(self.get_prom('port_lacp_state', labels=labels)))
        # Ensure LACP packet sent.
        valve = self.valves_manager.valves[self.DP_ID]
        ofmsgs = valve.fast_advertise(self.mock_time(), None)[valve]
        self.assertTrue(ValveTestBases.packet_outs_from_flows(ofmsgs))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            3, int(self.get_prom('port_lacp_state', labels=labels)))
        self.learn_hosts()
        self.verify_expiry()


class ValveL2LearnTestCase(ValveTestBases.ValveTestNetwork):
    """Test L2 Learning"""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_expiry(self):
        learn_labels = {
            'vid': str(0x200),
            'eth_src': self.P2_V200_MAC
        }
        self.assertEqual(
            0, self.get_prom('learned_l2_port', labels=learn_labels))
        self.learn_hosts()
        self.assertEqual(
            2.0, self.get_prom('learned_l2_port', labels=learn_labels))
        self.verify_expiry()
        self.assertEqual(
            0, self.get_prom('learned_l2_port', labels=learn_labels))


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
        routes:
            - route:
                ip_dst: 'fc00::10:0/112'
                ip_gw: 'fc00::1:1'
            - route:
                ip_dst: 'fc00::20:0/112'
                ip_gw: 'fc00::1:99'
routers:
    router1:
        bgp:
            as: 1
            connect_mode: 'passive'
            neighbor_as: 2
            port: 9179
            routerid: '1.1.1.1'
            server_addresses: ['127.0.0.1']
            neighbor_addresses: ['127.0.0.1']
            vlan: v100
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valves(self.CONFIG)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
