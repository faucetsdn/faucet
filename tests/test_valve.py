#!/usr/bin/env python

"""Unit tests run as PYTHONPATH=.. ./test_valve.py."""

# Copyright (C) 2015 Research and Innovation Advanced Network New Zealand Ltd.
# Copyright (C) 2015--2017 The Contributors
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

import os
import unittest
import tempfile
import shutil
from fakeoftable import FakeOFTable

from ryu.lib import mac
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.lib.packet import ethernet, arp, vlan, ipv4, ipv6, packet

from faucet.valve import valve_factory
from faucet.config_parser import dp_parser
from faucet import valve_packet


def build_pkt(pkt):
    layers = []
    if 'arp_target_ip' in pkt and 'arp_source_ip' in pkt:
        ethertype = 0x806
        layers.append(arp.arp(src_ip=pkt['arp_source_ip'], dst_ip=pkt['arp_target_ip']))
    elif 'ipv6_src' in pkt:
        ethertype = 0x86DD
        layers.append(ipv6.ipv6(src=pkt['ipv6_src'], dst=pkt['ipv6_src']))
    else:
        ethertype = 0x800
        if 'ipv4_src' in pkt:
            net = ipv4.ipv4(src=pkt['ipv4_src'], dst=pkt['ipv4_dst'])
        else:
            net = ipv4.ipv4()
        layers.append(net)
    if 'vid' in pkt:
        tpid = 0x8100
        layers.append(vlan.vlan(vid=pkt['vid'], ethertype=ethertype))
    else:
        tpid = ethertype
    eth = ethernet.ethernet(
        dst=pkt['eth_dst'],
        src=pkt['eth_src'],
        ethertype=tpid)
    layers.append(eth)
    result = packet.Packet()
    for layer in layers:
        result.add_protocol(layer)
    return (result, ethertype)


class ValveTestBase(unittest.TestCase):

    CONFIG = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
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
vlans:
    v100:
        vid: 0x100
        faucet_vips: ['10.0.0.254/24']
        routes:
            - route:
                ip_dst: 10.99.99.0/24
                ip_gw: 10.0.0.1
    v200:
        vid: 0x200
        faucet_vips: ['fc00::1:254/112']
        routes:
            - route:
                ip_dst: "fc00::10:0/112"
                ip_gw: "fc00::1:1"
"""

    DP_ID = 1
    NUM_PORTS = 5
    NUM_TABLES = 9
    P1_V100_MAC = '00:00:00:01:00:01'
    P2_V200_MAC = '00:00:00:02:00:02'
    P3_V200_MAC = '00:00:00:02:00:03'
    UNKNOWN_MAC = '00:00:00:04:00:04'
    V100 = 0x100|ofp.OFPVID_PRESENT
    V200 = 0x200|ofp.OFPVID_PRESENT

    def setup_valve(self, config):
        self.tmpdir = tempfile.mkdtemp()
        self.config_file = os.path.join(self.tmpdir, 'valve_unit.yaml')
        self.table = FakeOFTable(self.NUM_TABLES)
        dp = self.update_config(config)
        self.valve = valve_factory(dp)(dp, 'test_valve')

    def update_config(self, config):
        with open(self.config_file, 'w') as config_file:
            config_file.write(config)
        _, dps = dp_parser(self.config_file, 'test_valve')
        return dps[0]

    def connect_dp(self):
        port_nos = range(1, self.NUM_PORTS + 1)
        self.table.apply_ofmsgs(self.valve.datapath_connect(port_nos))
        for port_no in port_nos:
            self.set_port_up(port_no)

    def apply_new_config(self, config):
        new_dp = self.update_config(config)
        _, ofmsgs = self.valve.reload_config(new_dp)
        self.table.apply_ofmsgs(ofmsgs)

    def set_port_down(self, port_no):
        self.table.apply_ofmsgs(self.valve.port_status_handler(
            port_no, ofp.OFPPR_DELETE, None))

    def set_port_up(self, port_no):
        self.table.apply_ofmsgs(self.valve.port_status_handler(
            port_no, ofp.OFPPR_ADD, None))

    def flap_port(self, port_no):
        self.set_port_down(port_no)
        self.set_port_up(port_no)

    def arp_for_controller(self):
        self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': mac.BROADCAST_STR,
            'arp_source_ip': '10.0.0.1',
            'arp_destination_ip': '10.0.0.254'})

    def learn_hosts(self):
        """Learn some hosts."""
        self.arp_for_controller()
        self.rcv_packet(1, 0x100, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC})
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'vid': 0x200})
        self.rcv_packet(3, 0x200, {
            'eth_src': self.P3_V200_MAC,
            'eth_dst': self.P2_V200_MAC,
            'vid': 0x200})

    def setUp(self):
        self.setup_valve(self.CONFIG)
        self.connect_dp()
        self.learn_hosts()

    def rcv_packet(self, port, vid, match):
        pkt, eth_type = build_pkt(match)
        pkt.serialize()
        eth_pkt = valve_packet.parse_eth_pkt(pkt)
        pkt_meta = self.valve.parse_rcv_packet(
            port, vid, eth_type, pkt.data, len(pkt.data), pkt, eth_pkt)
        rcv_packet_ofmsgs = self.valve.rcv_packet(
            other_valves=[], pkt_meta=pkt_meta)
        self.table.apply_ofmsgs(rcv_packet_ofmsgs)
        resolve_ofmsgs = self.valve.resolve_gateways()
        self.table.apply_ofmsgs(resolve_ofmsgs)
        self.valve.advertise()
        self.valve.state_expire()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)


class ValveTestCase(ValveTestBase):

    def test_invalid_vlan(self):
        """Test that packets with incorrect vlan tagging get dropped."""

        matches = [
            {'in_port': 1, 'vlan_vid': 18|ofp.OFPVID_PRESENT},
            {'in_port': 1, 'vlan_vid': self.V100},
            {'in_port': 3, 'vlan_vid': 0}]
        for match in matches:
            self.assertFalse(
                self.table.is_output(match),
                msg="Packets with incorrect vlan tags are output")

    def test_unknown_eth_src(self):
        """Test that packets from unknown macs are sent to controller.

        Untagged packets should have VLAN tags pushed before they are sent to
        the controler.
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
        on the associated vlan"""
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
            {'in_port': 1, 'vlan_vid': 0, 'eth_src': self.P1_V100_MAC},
            {
                'in_port': 3,
                'vlan_vid': self.V200,
                'eth_dst': self.P1_V100_MAC
                },
            ]
        dp = self.valve.dp
        for match in matches:
            in_port = match['in_port']

            if 'vlan_vid' in match and\
               match['vlan_vid'] & ofp.OFPVID_PRESENT is not 0:
                valve_vlan = dp.vlans[match['vlan_vid'] & ~ofp.OFPVID_PRESENT]
            else:
                valve_vlan = self.valve.dp.get_native_vlan(in_port)

            remaining_ports = set(range(1, 6))

            # Check packets are output to each port on vlan
            for port in valve_vlan.get_ports():
                remaining_ports.discard(port.number)
                if port.number != in_port and port.running():
                    if valve_vlan.port_is_tagged(port):
                        vid = valve_vlan.vid|ofp.OFPVID_PRESENT
                    else:
                        vid = 0
                    self.assertTrue(
                        self.table.is_output(match, port=port.number, vid=vid),
                        msg=('Packet %s with unknown eth_dst not output '
                             'correctly on VLAN %u to port %u' % (
                                 match, valve_vlan.vid, port.number)))

            # Check packets are not output to ports not on vlan
            for port in remaining_ports:
                self.assertFalse(
                    self.table.is_output(match, port=port),
                    msg=('Packet with unknown eth_dst output to non-VLAN port %u' % port))

    def test_known_eth_src_rule(self):
        """Test that packets with known eth src addrs are not sent to controller."""
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
            'vlan_vid': 0x200})

        match = {'in_port': 2, 'vlan_vid': 0, 'eth_src': self.P2_V200_MAC}
        self.assertTrue(
            self.table.is_output(match, port=ofp.OFPP_CONTROLLER),
            msg='eth src rule not deleted when mac seen on another port')

    def test_known_eth_dst_rule(self):
        """Test that packets with known eth dst addrs are output correctly.

        Output to the correct port with the correct vlan tagging."""
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

    def test_mac_learning_vlan_separation(self):
        """Test that when a mac is seen on a second vlan the original vlan
        rules are unaffected."""
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P1_V100_MAC,
            'eth_dst': self.UNKNOWN_MAC,
            'vlan_vid': 0x200})

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
            'eth_src': self.P1_V100_MAC, 'eth_dst': self.UNKNOWN_MAC})
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

    def test_port_acl_deny(self):
        acl_config = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
        interfaces:
            p1:
                number: 1
                native_vlan: v100
            p2:
                number: 2
                native_vlan: v200
                tagged_vlans: [v100]
                acl_in: drop_non_ospf_ipv4
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
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
"""

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

        self.apply_new_config(acl_config)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='packet not blocked by acl')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='packet not allowed by acl')


class ValveACLTestCase(ValveTestBase):

    def test_vlan_acl_deny(self):
        acl_config = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
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
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
        acl_in: drop_non_ospf_ipv4
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
"""

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

        self.apply_new_config(acl_config)
        self.flap_port(2)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='Packet not allowed by ACL')


class ValveReloadConfigTestCase(ValveTestCase):
    """Repeats the tests after a config reload."""

    OLD_CONFIG = """
version: 2
dps:
    s1:
        ignore_learn_ins: 0
        hardware: 'Open vSwitch'
        dp_id: 1
        interfaces:
            p1:
                number: 1
                tagged_vlans: [v100, v200]
            p2:
                number: 2
                native_vlan: v100
            p3:
                number: 3
                tagged_vlans: [v100, v200]
            p4:
                number: 4
                tagged_vlans: [v200]
            p5:
                number: 5
vlans:
    v100:
        vid: 0x100
    v200:
        vid: 0x200
"""

    def setUp(self):
        self.setup_valve(self.OLD_CONFIG)
        self.connect_dp()
        self.flap_port(1)
        self.learn_hosts()

        self.apply_new_config(self.CONFIG)
        self.learn_hosts()


if __name__ == "__main__":
    unittest.main()
