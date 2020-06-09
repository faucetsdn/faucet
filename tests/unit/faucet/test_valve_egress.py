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


import unittest

from ryu.ofproto import ofproto_v1_3 as ofp

from clib.valve_test_lib import CONFIG, DP1_CONFIG, FAUCET_MAC, ValveTestBases


class ValveTestEgressPipeline(ValveTestBases.ValveTestBig):
    """Run complete set of basic tests."""

    DP1_CONFIG = """
            egress_pipeline: True
    """ + DP1_CONFIG


class ValveEgressACLTestCase(ValveTestBases.ValveTestNetwork):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valves(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        ALLOW_HOST_V6 = 'fc00:200::1:1'  # pylint: disable=invalid-name
        DENY_HOST_V6 = 'fc00:200::1:2'  # pylint: disable=invalid-name
        FAUCET_V100_VIP = 'fc00:100::1'  # pylint: disable=invalid-name
        FAUCET_V200_VIP = 'fc00:200::1'  # pylint: disable=invalid-name
        acl_config = """
dps:
    s1:
{dp1_config}
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
        faucet_mac: '{mac}'
        faucet_vips: ['{v100_vip}/64']
    v200:
        vid: 0x200
        faucet_mac: '{mac}'
        faucet_vips: ['{v200_vip}/64']
        acl_out: drop_non_allow_host_v6
        minimum_ip_size_check: no
routers:
    r_v100_v200:
        vlans: [v100, v200]
acls:
    drop_non_allow_host_v6:
        - rule:
            ipv6_dst: '{allow_host}'
            eth_type: 0x86DD
            actions:
                allow: 1
        - rule:
            eth_type: 0x86DD
            actions:
                allow: 0
""".format(dp1_config=DP1_CONFIG, mac=FAUCET_MAC, v100_vip=FAUCET_V100_VIP,
           v200_vip=FAUCET_V200_VIP, allow_host=ALLOW_HOST_V6)

        l2_drop_match = {
            'in_port': 2,
            'eth_dst': self.P3_V200_MAC,
            'vlan_vid': 0,
            'eth_type': 0x86DD,
            'ipv6_dst': DENY_HOST_V6}
        l2_accept_match = {
            'in_port': 3,
            'eth_dst': self.P2_V200_MAC,
            'vlan_vid': 0x200 | ofp.OFPVID_PRESENT,
            'eth_type': 0x86DD,
            'ipv6_dst': ALLOW_HOST_V6}
        v100_accept_match = {'in_port': 1, 'vlan_vid': 0}
        table = self.network.tables[self.DP_ID]

        # base case
        for match in (l2_drop_match, l2_accept_match):
            self.assertTrue(
                table.is_output(match, port=4),
                msg='Packet not output before adding ACL')

        # multicast
        self.update_config(acl_config, reload_type='cold')
        self.assertTrue(
            table.is_output(v100_accept_match, port=3),
            msg='Packet not output when on vlan with no ACL'
            )
        self.assertFalse(
            table.is_output(l2_drop_match, port=3),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            table.is_output(l2_accept_match, port=2),
            msg='Packet not allowed by ACL')

        # unicast
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'vid': 0x200,
            'ipv6_src': ALLOW_HOST_V6,
            'ipv6_dst': DENY_HOST_V6,
            'neighbor_advert_ip': ALLOW_HOST_V6,
            })
        self.rcv_packet(3, 0x200, {
            'eth_src': self.P3_V200_MAC,
            'eth_dst': self.P2_V200_MAC,
            'vid': 0x200,
            'ipv6_src': DENY_HOST_V6,
            'ipv6_dst': ALLOW_HOST_V6,
            'neighbor_advert_ip': DENY_HOST_V6,
            })

        self.assertTrue(
            table.is_output(l2_accept_match, port=2),
            msg='Packet not allowed by ACL')
        self.assertFalse(
            table.is_output(l2_drop_match, port=3),
            msg='Packet not blocked by ACL')

        # l3
        l3_drop_match = {
            'in_port': 1,
            'eth_dst': FAUCET_MAC,
            'vlan_vid': 0,
            'eth_type': 0x86DD,
            'ipv6_dst': DENY_HOST_V6}
        l3_accept_match = {
            'in_port': 1,
            'eth_dst': FAUCET_MAC,
            'vlan_vid': 0,
            'eth_type': 0x86DD,
            'ipv6_dst': ALLOW_HOST_V6}

        self.assertTrue(
            table.is_output(l3_accept_match, port=2),
            msg='Routed packet not allowed by ACL')
        self.assertFalse(
            table.is_output(l3_drop_match, port=3),
            msg='Routed packet not blocked by ACL')


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
