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



from collections import namedtuple
from functools import partial

import hashlib
import os
import time
import unittest

from prometheus_client import CollectorRegistry
from ryu.controller import dpset
from ryu.controller.ofp_event import EventOFPMsgBase
from ryu.lib.packet import slow
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from faucet import config_parser_util
from faucet import faucet
from faucet import faucet_dot1x
from faucet import faucet_experimental_api
from faucet import valve_of


from valve_test_lib import (
    CONFIG,
    DP1_CONFIG, DOT1X_CONFIG, DOT1X_ACL_CONFIG,
    FAUCET_MAC, GROUP_DP1_CONFIG, IDLE_DP1_CONFIG,
    ValveTestBases)



class ValveTestCase(ValveTestBases.ValveTestBig):
    """Run complete set of basic tests."""



class ValveTestEgressPipeline(ValveTestBases.ValveTestBig):
    """Run complete set of basic tests."""

    DP1_CONFIG = """
            egress_pipeline: True
    """ + DP1_CONFIG


class ValveIncludeTestCase(ValveTestBases.ValveTestSmall):
    """Test include optional files."""

    CONFIG = """
include-optional: ['/does/not/exist/']
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_include_optional(self):
        """Test include optional files."""
        self.assertEqual(1, int(self.get_prom('dp_status')))


class ValveBadConfTestCase(ValveTestBases.ValveTestSmall):
    """Test recovery from a bad config file."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
""" % DP1_CONFIG

    MORE_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
            p2:
                number: 2
                native_vlan: 0x100
""" % DP1_CONFIG

    BAD_CONFIG = """
dps: {}
"""

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_bad_conf(self):
        for config, load_error in (
                (self.CONFIG, 0),
                (self.BAD_CONFIG, 1),
                (self.CONFIG, 0),
                (self.MORE_CONFIG, 0),
                (self.BAD_CONFIG, 1),
                (self.CONFIG, 0)):
            with open(self.config_file, 'w') as config_file:
                config_file.write(config)
            self.valves_manager.request_reload_configs(time.time(), self.config_file)
            self.assertEqual(
                load_error,
                self.get_prom('faucet_config_load_error', bare=True),
                msg='%u: %s' % (load_error, config))


class ValveFuzzTestCase(ValveTestBases.ValveTestSmall):
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
        self.setup_valve(self.CONFIG)

    def test_fuzz_vlan(self):
        """Test unknown VIDs/ports."""
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


class ValveDot1xSmokeTestCase(ValveTestBases.ValveTestSmall):
    """Smoke test to check dot1x can be initialized."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
    student:
        vid: 0x200
        dot1x_assigned: True

""" % DOT1X_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_get_mac_str(self):
        """Test NFV port formatter."""
        self.assertEqual('00:00:00:0f:01:01', faucet_dot1x.get_mac_str(15, 257))

    def test_handlers(self):
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        port_no = 1
        vlan_name = 'student'
        filter_id = 'block_http'
        for handler in (
                self.dot1x.logoff_handler,
                self.dot1x.failure_handler):
            handler(
                '0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no))
        self.dot1x.auth_handler(
            '0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no),
            vlan_name=vlan_name, filter_id=filter_id)


class ValveDot1xACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized."""
    ACL_CONFIG = """
acls:
    auth_acl:
        - rule:
            actions:
                allow: 1
    noauth_acl:
        - rule:
            actions:
                allow: 0
"""

    CONFIG = """
{}
dps:
    s1:
{}
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_acl: True
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
    student:
        vid: 0x200
        dot1x_assigned: True
""".format(ACL_CONFIG, DOT1X_ACL_CONFIG)


class ValveDot1xMABSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized."""

    CONFIG = """
dps:
    s1:
{}
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_mab: True
            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
""".format(DOT1X_CONFIG)


class ValveDot1xDynACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized."""
    CONFIG = """
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
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: v100
                dot1x: true
                dot1x_dyn_acl: True

            p2:
                number: 2
                output_only: True
vlans:
    v100:
        vid: 0x100
""" % DOT1X_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_handlers(self):
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        port_no = 1
        vlan_name = None
        filter_id = 'accept_acl'
        for handler in (
                self.dot1x.logoff_handler,
                self.dot1x.failure_handler):
            handler(
                '0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no))
        self.dot1x.auth_handler(
            '0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no),
            vlan_name=vlan_name, filter_id=filter_id)


class ValveChangePortTestCase(ValveTestBases.ValveTestSmall):
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

    def test_delete_permanent_learn(self):
        """Test port permanent learn can deconfigured."""
        self.rcv_packet(2, 0x200, {
            'eth_src': self.P2_V200_MAC,
            'eth_dst': self.P3_V200_MAC,
            'ipv4_src': '10.0.0.2',
            'ipv4_dst': '10.0.0.3',
            'vid': 0x200})
        self.update_config(self.LESS_CONFIG, reload_type='warm')


class ValveDeletePortTestCase(ValveTestBases.ValveTestSmall):
    """Test deletion of a port."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
""" % DP1_CONFIG

    LESS_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_port_delete(self):
        """Test port can be deleted."""
        self.update_config(self.LESS_CONFIG, reload_type='cold')


class ValveAddPortTestCase(ValveTestBases.ValveTestSmall):
    """Test addition of a port."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
""" % DP1_CONFIG

    MORE_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100]
            p2:
                number: 2
                tagged_vlans: [0x100]
            p3:
                number: 3
                tagged_vlans: [0x100]
""" % DP1_CONFIG

    def _inport_flows(self, in_port, ofmsgs):
        return [
            ofmsg for ofmsg in self.flowmods_from_flows(ofmsgs)
            if ofmsg.match.get('in_port') == in_port]

    def setUp(self):
        initial_ofmsgs = self.setup_valve(self.CONFIG)
        self.assertFalse(self._inport_flows(3, initial_ofmsgs))

    def test_port_add(self):
        """Test port can be added."""
        reload_ofmsgs = self.update_config(self.MORE_CONFIG, reload_type='cold')
        self.assertTrue(self._inport_flows(3, reload_ofmsgs))


class ValveWarmStartVLANTestCase(ValveTestBases.ValveTestSmall):
    """Test change of port VLAN only is a warm start."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x200
""" % DP1_CONFIG

    WARM_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 9
                tagged_vlans: [0x100]
            p2:
                number: 11
                tagged_vlans: [0x100]
            p3:
                number: 13
                tagged_vlans: [0x100]
            p4:
                number: 14
                native_vlan: 0x300
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_warm_start(self):
        """Test VLAN change is warm startable."""
        self.update_config(self.WARM_CONFIG, reload_type='warm')


class ValveDeleteVLANTestCase(ValveTestBases.ValveTestSmall):
    """Test deleting VLAN."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    LESS_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x200]
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_delete_vlan(self):
        """Test VLAN can be deleted."""
        self.update_config(self.LESS_CONFIG, reload_type='warm')


class ValveOFErrorTestCase(ValveTestBases.ValveTestSmall):
    """Test decoding of OFErrors."""

    def setUp(self):
        self.setup_valve(CONFIG)

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
        self.valve.oferror(test_err)
        test_unknown_type_err = parser.OFPErrorMsg(
            datapath=None, type_=666, code=ofp.OFPFMFC_UNKNOWN)
        self.valve.oferror(test_unknown_type_err)
        test_unknown_code_err = parser.OFPErrorMsg(
            datapath=None, type_=ofp.OFPET_FLOW_MOD_FAILED, code=666)
        self.valve.oferror(test_unknown_code_err)


class ValveAddVLANTestCase(ValveTestBases.ValveTestSmall):
    """Test adding VLAN."""

    CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100]
""" % DP1_CONFIG

    MORE_CONFIG = """
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                tagged_vlans: [0x100, 0x200]
            p2:
                number: 2
                tagged_vlans: [0x100, 0x300]
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_add_vlan(self):
        """Test VLAN can added."""
        self.update_config(self.MORE_CONFIG, reload_type='warm')


class ValveChangeACLTestCase(ValveTestBases.ValveTestSmall):
    """Test changes to ACL on a port."""

    CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_a
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    SAME_CONTENT_CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_same_b
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    DIFF_CONTENT_CONFIG = """
acls:
    acl_same_a:
        - rule:
            actions:
                allow: 1
    acl_same_b:
        - rule:
            actions:
                allow: 1
    acl_diff_c:
        - rule:
            actions:
                allow: 0
dps:
    s1:
%s
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
                acl_in: acl_diff_c
            p2:
                number: 2
                native_vlan: 0x200
""" % DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_change_port_acl(self):
        """Test port ACL can be changed."""
        self.update_config(self.SAME_CONTENT_CONFIG, reload_type='warm')
        self.update_config(self.DIFF_CONTENT_CONFIG, reload_type='warm')


class ValveACLTestCase(ValveTestBases.ValveTestSmall):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        acl_config = """
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

        self.update_config(acl_config, reload_type='cold')
        self.flap_port(2)
        self.assertFalse(
            self.table.is_output(drop_match),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(accept_match, port=3, vid=self.V200),
            msg='Packet not allowed by ACL')


class ValveEgressACLTestCase(ValveTestBases.ValveTestSmall):
    """Test ACL drop/allow and reloading."""

    def setUp(self):
        self.setup_valve(CONFIG)

    def test_vlan_acl_deny(self):
        """Test VLAN ACL denies a packet."""
        ALLOW_HOST_V6 = 'fc00:200::1:1'
        DENY_HOST_V6 = 'fc00:200::1:2'
        FAUCET_V100_VIP = 'fc00:100::1'
        FAUCET_V200_VIP = 'fc00:200::1'
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

        # base case
        for match in (l2_drop_match, l2_accept_match):
            self.assertTrue(
                self.table.is_output(match, port=4),
                msg='Packet not output before adding ACL')

        # multicast
        self.update_config(acl_config, reload_type='cold')
        self.assertTrue(
            self.table.is_output(v100_accept_match, port=3),
            msg='Packet not output when on vlan with no ACL'
            )
        self.assertFalse(
            self.table.is_output(l2_drop_match, port=3),
            msg='Packet not blocked by ACL')
        self.assertTrue(
            self.table.is_output(l2_accept_match, port=2),
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
            self.table.is_output(l2_accept_match, port=2),
            msg='Packet not allowed by ACL')
        self.assertFalse(
            self.table.is_output(l2_drop_match, port=3),
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
            self.table.is_output(l3_accept_match, port=2),
            msg='Routed packet not allowed by ACL')
        self.assertFalse(
            self.table.is_output(l3_drop_match, port=3),
            msg='Routed packet not blocked by ACL')


class ValveReloadConfigProfile(ValveTestBases.ValveTestSmall):

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
        pstats_out, _ = self.profile(partial(self.setup_valve, self.CONFIG))
        self.baseline_total_tt = pstats_out.total_tt # pytype: disable=attribute-error

    def test_profile_reload(self):
        for i in range(2, 100):
            self.CONFIG += """
            p%u:
                number: %u
                native_vlan: 0x100
""" % (i, i)
        pstats_out, pstats_text = self.profile(
            partial(self.update_config, self.CONFIG, reload_type='cold'))
        total_tt_prop = pstats_out.total_tt / self.baseline_total_tt # pytype: disable=attribute-error
        # must not be 50x slower, to ingest config for 100 interfaces than 1.
        self.assertLessEqual(total_tt_prop, 50, msg=pstats_text)


class ValveTestConfigHash(ValveTestBases.ValveTestSmall):
    """Verify faucet_config_hash_info update after config change"""

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
        self.setup_valve(self.CONFIG)

    def _get_info(self, metric, name):
        """"Return (single) info dict for metric"""
        # There doesn't seem to be a nice API for this,
        # so we use the prometheus client internal API
        metrics = list(metric.collect())
        self.assertEqual(len(metrics), 1)
        samples = metrics[0].samples
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.name, name)
        return sample.labels

    def _check_hashes(self):
        """Verify and return faucet_config_hash_info labels"""
        labels = self._get_info(metric=self.metrics.faucet_config_hash,
                                name='faucet_config_hash_info')
        files = labels['config_files'].split(',')
        hashes = labels['hashes'].split(',')
        self.assertTrue(len(files) == len(hashes) == 1)
        self.assertEqual(files[0], self.config_file, 'wrong config file')
        hash_value = config_parser_util.config_file_hash(self.config_file)
        self.assertEqual(hashes[0], hash_value, 'hash validation failed')
        return labels

    def _change_config(self):
        """Change self.CONFIG"""
        if '0x100' in self.CONFIG:
            self.CONFIG = self.CONFIG.replace('0x100', '0x200')
        else:
            self.CONFIG = self.CONFIG.replace('0x200', '0x100')
        self.update_config(self.CONFIG, reload_expected=True)
        return self.CONFIG

    def test_config_hash_func(self):
        """Verify that faucet_config_hash_func is set correctly"""
        labels = self._get_info(metric=self.metrics.faucet_config_hash_func,
                                name='faucet_config_hash_func')
        hash_funcs = list(labels.values())
        self.assertEqual(len(hash_funcs), 1, "found multiple hash functions")
        hash_func = hash_funcs[0]
        # Make sure that it matches and is supported in hashlib
        self.assertEqual(hash_func, config_parser_util.CONFIG_HASH_FUNC)
        self.assertTrue(hash_func in hashlib.algorithms_guaranteed)

    def test_config_hash_update(self):
        """Verify faucet_config_hash_info is properly updated after config"""
        # Verify that hashes change after config is changed
        old_config = self.CONFIG
        old_hashes = self._check_hashes()
        starting_hashes = old_hashes
        self._change_config()
        new_config = self.CONFIG
        self.assertNotEqual(old_config, new_config, 'config not changed')
        new_hashes = self._check_hashes()
        self.assertNotEqual(old_hashes, new_hashes,
                            'hashes not changed after config change')
        # Verify that hashes don't change after config isn't changed
        old_hashes = new_hashes
        self.update_config(self.CONFIG, reload_expected=False)
        new_hashes = self._check_hashes()
        self.assertEqual(old_hashes, new_hashes,
                         "hashes changed when config didn't")
        # Verify that hash is restored when config is restored
        self._change_config()
        new_hashes = self._check_hashes()
        self.assertEqual(new_hashes, starting_hashes,
                         'hashes should be restored to starting values')



class ValveTestConfigApplied(ValveTestBases.ValveTestSmall):
    """Test cases for faucet_config_applied"""
    CONFIG = """
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def _get_value(self, name):
        """Return value of a single prometheus sample"""
        metric = getattr(self.metrics, name)
        # There doesn't seem to be a nice API for this,
        # so we use the prometheus client internal API
        metrics = list(metric.collect())
        self.assertEqual(len(metrics), 1)
        samples = metrics[0].samples
        self.assertEqual(len(samples), 1)
        sample = samples[0]
        self.assertEqual(sample.name, name)
        return sample.value

    def test_config_applied_update(self):
        """Verify that config_applied increments after DP connect"""
        # 100% for a single datapath
        self.assertEqual(self._get_value('faucet_config_applied'), 1.0)
        # Add a second datapath, which currently isn't programmed
        self.CONFIG += """
    s2:
        dp_id: 0x2
        interfaces:
            p1:
                number: 1
                native_vlan: 0x100
"""
        self.update_config(self.CONFIG, reload_expected=False)
        # Should be 50%
        self.assertEqual(self._get_value('faucet_config_applied'), .5)
        # We don't have a way to simulate the second datapath connecting,
        # we update the statistic manually
        self.valves_manager.update_config_applied({0x2: True})
        # Should be 100% now
        self.assertEqual(self._get_value('faucet_config_applied'), 1.0)


class ValveGroupTestCase(ValveTestBases.ValveTestSmall):
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
        self.setup_valve(self.CONFIG)

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            1, int(self.get_prom('port_lacp_status', labels=labels)))
        self.learn_hosts()
        self.verify_expiry()

    def test_lacp_flap(self):
        """Test LACP handles state 0->1->0."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            1, int(self.get_prom('port_lacp_status', labels=labels)))
        self.learn_hosts()
        self.verify_expiry()
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 0})
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))

    def test_lacp_timeout(self):
        """Test LACP comes up and then times out."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            1, int(self.get_prom('port_lacp_status', labels=labels)))
        future_now = time.time() + 10
        expire_ofmsgs = self.valve.state_expire(future_now, None)
        self.assertTrue(expire_ofmsgs)
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))


class ValveActiveLACPTestCase(ValveTestBases.ValveTestSmall):
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
        self.setup_valve(self.CONFIG)

    def test_lacp(self):
        """Test LACP comes up."""
        test_port = 1
        labels = self.port_labels(test_port)
        self.assertEqual(
            0, int(self.get_prom('port_lacp_status', labels=labels)))
        # Ensure LACP packet sent.
        ofmsgs = self.valve.fast_advertise(time.time(), None)[self.valve]
        self.assertTrue(self.packet_outs_from_flows(ofmsgs))
        self.rcv_packet(test_port, 0, {
            'actor_system': '0e:00:00:00:00:02',
            'partner_system': FAUCET_MAC,
            'eth_dst': slow.SLOW_PROTOCOL_MULTICAST,
            'eth_src': '0e:00:00:00:00:02',
            'actor_state_synchronization': 1})
        self.assertEqual(
            1, int(self.get_prom('port_lacp_status', labels=labels)))
        self.learn_hosts()
        self.verify_expiry()


class ValveReloadConfigTestCase(ValveTestBases.ValveTestBig):
    """Repeats the tests after a config reload."""

    def setUp(self):
        super(ValveReloadConfigTestCase, self).setUp()
        self.flap_port(1)
        self.update_config(CONFIG, reload_type='warm', reload_expected=False)


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
