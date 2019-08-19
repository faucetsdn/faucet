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
from ryu.lib import mac
from ryu.lib.packet import slow
from ryu.ofproto import ofproto_v1_3 as ofp
from ryu.ofproto import ofproto_v1_3_parser as parser

from faucet import config_parser_util
from faucet import faucet
from faucet import faucet_dot1x
from faucet import faucet_experimental_api
from faucet import valve_of
from faucet import valves_manager


from valve_test_lib import (
    BASE_DP1_CONFIG, CONFIG,
    DP1_CONFIG, DOT1X_CONFIG, DOT1X_ACL_CONFIG,
    FAUCET_MAC, GROUP_DP1_CONFIG, IDLE_DP1_CONFIG,
    STACK_CONFIG,
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


class ValveStackRootExtLoopProtectTestCase(ValveTestBases.ValveTestSmall):

    CONFIG = """
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
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)
        self.set_stack_port_up(1)

    def test_loop_protect(self):
        mcast_match = {
            'in_port': 2,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5',
        }
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to non-root stack')
        self.assertTrue(
            self.table.is_output(mcast_match, port=3),
            msg='mcast packet not flooded locally on root')
        self.assertFalse(
            self.table.is_output(mcast_match, port=4),
            msg='mcast packet multiply flooded externally on root')


class ValveStackNonRootExtLoopProtectTestCase(ValveTestBases.ValveTestSmall):

    CONFIG = """
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
                native_vlan: 100
            3:
                description: p3
                native_vlan: 100
                loop_protect_external: True
            4:
                description: p4
                native_vlan: 100
                loop_protect_external: True
    s2:
        hardware: 'GenericTFM'
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
                    port: 1
            3:
                description: p2
                native_vlan: 100
    s3:
        hardware: 'GenericTFM'
        dp_id: 0x3
        stack:
            priority: 1
        interfaces:
            1:
                description: p1
                stack:
                    dp: s2
                    port: 2
            2:
                description: p2
                native_vlan: 100
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)
        self.set_stack_port_up(1)

    def test_loop_protect(self):
        mcast_match = {
            'in_port': 2,
            'eth_dst': mac.BROADCAST_STR,
            'vlan_vid': 0,
            'eth_type': 0x800,
            'ipv4_dst': '224.0.0.5',
        }
        self.assertTrue(
            self.table.is_output(mcast_match, port=1),
            msg='mcast packet not flooded to root of stack')
        self.assertFalse(
            self.table.is_output(mcast_match, port=3),
            msg='mcast packet flooded locally on non-root')
        self.assertFalse(
            self.table.is_output(mcast_match, port=4),
            msg='mcast packet flooded locally on non-root')


class ValveStackAndNonStackTestCase(ValveTestBases.ValveTestSmall):

    CONFIG = """
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
                native_vlan: 0x100
    s2:
        hardware: 'GenericTFM'
        dp_id: 0x2
        interfaces:
            1:
                description: p1
                stack:
                    dp: s1
                    port: 1
            2:
                description: p2
                native_vlan: 0x100
    s3:
        hardware: 'GenericTFM'
        dp_id: 0x3
        interfaces:
            1:
                description: p1
                native_vlan: 0x100
            2:
                description: p2
                native_vlan: 0x100
""" % BASE_DP1_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_nonstack_dp_port(self):
        self.assertEqual(None, self.valves_manager.valves[0x3].dp.shortest_path_port('s1'))


class ValveStackRedundancyTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for updating the stack graph"""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_redundancy(self):
        now = 1
        # All switches are down to start with.
        for dpid in self.valves_manager.valves:
            self.valves_manager.valves[dpid].dp.dyn_running = False
        for valve in self.valves_manager.valves.values():
            self.assertFalse(valve.dp.dyn_running)
            self.assertEqual('s1', valve.dp.stack_root_name)
        # From a cold start - we pick the s1 as root.
        self.assertEqual(None, self.valves_manager.meta_dp_state.stack_root_name)
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        now += (valves_manager.STACK_ROOT_DOWN_TIME * 2)
        # Time passes, still no change, s1 is still the root.
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))
        # s2 has come up, but s1 is still down. We expect s2 to be the new root.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now
        now += (valves_manager.STACK_ROOT_STATE_UPDATE_TIME * 2)
        self.assertTrue(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        # More time passes, s1 is still down, s2 is still the root.
        now += (valves_manager.STACK_ROOT_DOWN_TIME * 2)
        # s2 recently said something, s2 still the root.
        self.valves_manager.meta_dp_state.dp_last_live_time['s2'] = now - 1
        self.assertFalse(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s2', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(2, self.get_prom('faucet_stack_root_dpid', bare=True))
        # now s1 came up too, so we change to s1 because we prefer it.
        self.valves_manager.meta_dp_state.dp_last_live_time['s1'] = now + 1
        now += valves_manager.STACK_ROOT_STATE_UPDATE_TIME
        self.assertTrue(self.valves_manager.maintain_stack_root(now))
        self.assertEqual('s1', self.valves_manager.meta_dp_state.stack_root_name)
        self.assertEqual(1, self.get_prom('faucet_stack_root_dpid', bare=True))


class ValveRootStackTestCase(ValveTestBases.ValveTestSmall):
    """Test stacking/forwarding."""

    DP = 's3'
    DP_ID = 0x3

    def setUp(self):
        self.setup_valve(CONFIG)
        self.set_stack_port_up(5)

    def test_stack_learn(self):
        """Test host learning on stack root."""
        self.prom_inc(
            partial(self.rcv_packet, 1, 0x300, {
                'eth_src': self.P1_V300_MAC,
                'eth_dst': self.UNKNOWN_MAC,
                'ipv4_src': '10.0.0.1',
                'ipv4_dst': '10.0.0.2'}),
            'vlan_hosts_learned',
            labels={'vlan': str(int(0x300))})

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
        self.set_stack_port_up(5)

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

    def test_no_unexpressed_packetin(self):
        """Test host learning on stack root."""
        unexpressed_vid = 0x666 | ofp.OFPVID_PRESENT
        match = {
            'vlan_vid': unexpressed_vid,
            'eth_dst': self.UNKNOWN_MAC}
        self.assertFalse(
            self.table.is_output(match, port=ofp.OFPP_CONTROLLER, vid=unexpressed_vid))


class ValveStackProbeTestCase(ValveTestBases.ValveTestSmall):
    """Test stack link probing."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_stack_probe(self):
        """Test probing works correctly."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(self.valve)
        self.valve.fast_state_expire(time.time(), other_valves)
        self.assertTrue(stack_port.is_stack_init())
        for change_func, check_func in [
                ('stack_up', 'is_stack_up'),
                ('stack_down', 'is_stack_down')]:
            getattr(other_port, change_func)()
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(getattr(stack_port, check_func)())

    def test_stack_miscabling(self):
        """Test probing stack with miscabling."""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        wrong_port = other_dp.ports[2]
        wrong_dp = self.valves_manager.valves[3].dp
        other_valves = self.valves_manager._other_running_valves(self.valve)
        self.valve.fast_state_expire(time.time(), other_valves)
        for remote_dp, remote_port in [
                (wrong_dp, other_port),
                (other_dp, wrong_port)]:
            self.rcv_lldp(stack_port, other_dp, other_port)
            self.assertTrue(stack_port.is_stack_down() or stack_port.is_stack_init())
            self.rcv_lldp(stack_port, remote_dp, remote_port)
            self.assertTrue(stack_port.is_stack_down())

    def test_stack_lost_lldp(self):
        """Test stacking when LLDP packets get dropped"""
        stack_port = self.valve.dp.ports[1]
        other_dp = self.valves_manager.valves[2].dp
        other_port = other_dp.ports[1]
        other_valves = self.valves_manager._other_running_valves(self.valve)
        self.valve.fast_state_expire(time.time(), other_valves)
        self.rcv_lldp(stack_port, other_dp, other_port)
        self.assertTrue(stack_port.is_stack_init())
        self.valve.fast_state_expire(time.time() + 300, other_valves) # simulate packet loss
        self.assertTrue(stack_port.is_stack_down())


class ValveStackGraphUpdateTestCase(ValveTestBases.ValveTestSmall):
    """Valve test for updating the stack graph."""

    CONFIG = STACK_CONFIG

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def test_update_stack_graph(self):
        """Test stack graph port UP and DOWN updates"""

        def all_stack_up():
            for valve in self.valves_manager.valves.values():
                valve.dp.dyn_running = True
                for port in valve.dp.stack_ports:
                    port.stack_up()

        def up_stack_port(port):
            peer_dp = port.stack['dp']
            peer_port = port.stack['port']
            for state_func in [peer_port.stack_init, peer_port.stack_up]:
                state_func()
                self.rcv_lldp(port, peer_dp, peer_port)
            self.assertTrue(port.is_stack_up())

        def down_stack_port(port):
            up_stack_port(port)
            peer_port = port.stack['port']
            peer_port.stack_down()
            self.valves_manager.valve_flow_services(
                time.time() + 600,
                'fast_state_expire')
            self.assertTrue(port.is_stack_down())

        def verify_stack_learn_edges(num_edges, edge=None, test_func=None):
            for dpid in (1, 2, 3):
                valve = self.valves_manager.valves[dpid]
                if not valve.dp.stack:
                    continue
                graph = valve.dp.stack['graph']
                self.assertEqual(num_edges, len(graph.edges()))
                if test_func and edge:
                    test_func(edge in graph.edges(keys=True))

        num_edges = 3
        all_stack_up()
        verify_stack_learn_edges(num_edges)
        ports = [self.valve.dp.ports[1], self.valve.dp.ports[2]]
        edges = [('s1', 's2', 's1:1-s2:1'), ('s1', 's2', 's1:2-s2:2')]
        for port, edge in zip(ports, edges):
            num_edges -= 1
            down_stack_port(port)
            verify_stack_learn_edges(num_edges, edge, self.assertFalse)
        up_stack_port(ports[0])
        verify_stack_learn_edges(2, edges[0], self.assertTrue)


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


class ValveTestTunnel(ValveTestBases.ValveTestSmall):
    """Test valve tunnel methods"""
    TUNNEL_ID = 200
    CONFIG = """
acls:
    tunnel_acl:
        - rule:
            actions:
                output:
                    tunnel: {type: 'vlan', tunnel_id: %u, dp: s3, port: 1}
vlans:
    vlan100:
        vid: 100
dps:
    s1:
        dp_id: 0x1
        hardware: 'GenericTFM'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack:
                    dp: s2
                    port: 2
            3:
                stack:
                    dp: s2
                    port: 3
            4:
                stack:
                    dp: s3
                    port: 2
            5:
                stack:
                    dp: s3
                    port: 3
    s2:
        dp_id: 0x2
        interfaces:
            1:
                native_vlan: vlan100
                acls_in: [tunnel_acl]
            2:
                stack:
                    dp: s1
                    port: 2
            3:
                stack:
                    dp: s1
                    port: 3
    s3:
        dp_id: 0x3
        interfaces:
            1:
                native_vlan: vlan100
            2:
                stack:
                    dp: s1
                    port: 4
            3:
                stack:
                    dp: s1
                    port: 5
""" % TUNNEL_ID

    def setUp(self):
        self.setup_valve(self.CONFIG)

    def all_stack_up(self):
        """Force stack ports UP and enabled"""
        for valve in self.valves_manager.valves.values():
            valve.dp.dyn_running = True
            for port in valve.dp.stack_ports:
                port.stack_up()
                port.dyn_finalized = False
                port.enabled = True
                port.dyn_phys_up = True
                port.dyn_finalized = True

    @staticmethod
    def down_stack_port(port):
        """Force stack port DOWN"""
        peer_port = port.stack['port']
        peer_port.stack_down()
        port.dyn_finalized = False
        port.enabled = False
        port.dyn_phys_up = False
        port.dyn_finalized = True

    def update_all_flowrules(self):
        """Update all valve tunnel flowrules"""
        for valve in self.valves_manager.valves.values():
            valve.update_tunnel_flowrules()

    def update_all_tunnels(self, state):
        """Force DP tunnel updated flag state"""
        for valve in self.valves_manager.valves.values():
            valve.dp.tunnel_updated_flags[self.TUNNEL_ID] = state

    def get_valve(self, dp_id):
        """Get valve with dp_id"""
        return self.valves_manager.valves[dp_id]

    def test_update_on_stack_link_up(self):
        """Test updating acl tunnel rules on stack link status UP"""
        self.all_stack_up()
        self.update_all_flowrules()
        for valve in self.valves_manager.valves.values():
            self.assertTrue(valve.dp.tunnel_updated_flags[self.TUNNEL_ID])

    def test_update_on_stack_link_down(self):
        """Test updating acl tunnel rules on stack link status DOWN"""
        self.all_stack_up()
        self.update_all_flowrules()
        self.update_all_tunnels(False)
        self.down_stack_port(self.get_valve(0x1).dp.ports[2])
        self.down_stack_port(self.get_valve(0x1).dp.ports[4])
        self.down_stack_port(self.get_valve(0x2).dp.ports[2])
        self.down_stack_port(self.get_valve(0x3).dp.ports[2])
        self.update_all_flowrules()
        self.assertTrue(self.get_valve(0x1).dp.tunnel_updated_flags[self.TUNNEL_ID])
        self.assertTrue(self.get_valve(0x2).dp.tunnel_updated_flags[self.TUNNEL_ID])

    def test_tunnel_flowmod_count(self):
        """Test the correct number of tunnel flowmods are created"""
        for valve in self.valves_manager.valves.values():
            self.assertEqual(len(valve.get_tunnel_flowmods()), 0)
        self.all_stack_up()
        self.update_all_flowrules()
        self.assertEqual(len(self.get_valve(0x1).get_tunnel_flowmods()), 2)
        self.assertEqual(len(self.get_valve(0x2).get_tunnel_flowmods()), 1)
        self.assertEqual(len(self.get_valve(0x3).get_tunnel_flowmods()), 2)


class ValveTestIPV4StackedRouting(ValveTestBases.ValveTestStackedRouting):
    """Test inter-vlan routing with stacking capabilities in an IPV4 network"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV4StackedRoutingDPOneVLAN(ValveTestBases.ValveTestStackedRouting):
    """Test stacked intervlan routing when each DP has only one of the routed VLANs"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'

    def base_config(self):
        """Create the base config"""
        self.V100_HOSTS = [1]
        self.V200_HOSTS = [2]
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
                3:
                    stack: {dp: s2, port: 3}
        s2:
            dp_id: 2
            interfaces:
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s1, port: 3}
    """

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV4StackedRoutingPathNoVLANS(ValveTestBases.ValveTestStackedRouting):
    """Test stacked intervlan routing when DP in path contains no routed VLANs"""

    VLAN100_FAUCET_VIPS = '10.0.1.254'
    VLAN100_FAUCET_VIP_SPACE = '10.0.1.254/24'
    VLAN200_FAUCET_VIPS = '10.0.2.254'
    VLAN200_FAUCET_VIP_SPACE = '10.0.2.254/24'

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
        vlan300:
            vid: 0x300
    %s
           """ % (self.VLAN100_FAUCET_MAC, self.VLAN100_FAUCET_VIP_SPACE,
                  self.VLAN200_FAUCET_MAC, self.VLAN200_FAUCET_VIP_SPACE,
                  self.base_config())

    def base_config(self):
        """Create the base config"""
        self.V100_HOSTS = [1]
        self.V200_HOSTS = [3]
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
                3:
                    stack: {dp: s2, port: 3}
        s2:
            dp_id: 2
            interfaces:
                2:
                    native_vlan: vlan300
                3:
                    stack: {dp: s1, port: 3}
                4:
                    stack: {dp: s3, port: 3}
        s3:
            dp_id: 3
            interfaces:
                2:
                    native_vlan: vlan200
                3:
                    stack: {dp: s2, port: 4}
                4:
                    stack: {dp: s4, port: 3}
        s4:
            dp_id: 4
            interfaces:
                2:
                    native_vlan: vlan300
                3:
                    stack: {dp: s3, port: 4}
    """

    def setUp(self):
        self.setup_stack_routing()


class ValveTestIPV6StackedRouting(ValveTestBases.ValveTestStackedRouting):
    """Test inter-vlan routing with stacking capabilities in an IPV6 network"""

    VLAN100_FAUCET_VIPS = 'fc80::1:254'
    VLAN200_FAUCET_VIPS = 'fc80::2:254'
    VLAN100_FAUCET_VIP_SPACE = 'fc80::1:254/64'
    VLAN200_FAUCET_VIP_SPACE = 'fc80::1:254/64'

    def setUp(self):
        self.setup_stack_routing()

    @staticmethod
    def create_ip(vindex, host):
        """Create a IP address string"""
        return 'fc80::%u:%u' % (vindex, host)

    @staticmethod
    def get_eth_type():
        """Returns IPV6 ether type"""
        return valve_of.ether.ETH_TYPE_IPV6

    def create_match(self, vindex, host, faucet_mac, faucet_vip, code):
        """Create an NA message"""
        return {
            'eth_src': self.create_mac(vindex, host),
            'eth_dst': faucet_mac,
            'ipv6_src': self.create_ip(vindex, host),
            'ipv6_dst': faucet_vip,
            'neighbor_advert_ip': self.create_ip(vindex, host)
        }


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
