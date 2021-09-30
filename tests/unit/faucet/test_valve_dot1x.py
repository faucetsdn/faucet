#!/usr/bin/env python3

"""Unit tests run as PYTHONPATH=../../.. python3 ./test_valve_dot1x.py."""

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

from faucet import faucet_dot1x

from clib.valve_test_lib import DOT1X_CONFIG, DOT1X_ACL_CONFIG, ValveTestBases


class ValveDot1xSmokeTestCase(ValveTestBases.ValveTestNetwork):
    """Smoke test to check dot1x can be initialized."""

    CONFIG = f"""
dps:
    s1:
{DOT1X_CONFIG}
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

"""

    def setUp(self):
        """Setup basic 802.1x config"""
        self.setup_valves(self.CONFIG)

    def test_get_mac_str(self):
        """Test NFV port formatter."""
        self.assertEqual('00:00:00:0f:01:01', faucet_dot1x.get_mac_str(15, 257))

    def test_handlers(self):
        """Test dot1x logoff/failure handlers."""
        valve_index = self.dot1x.dp_id_to_valve_index[self.DP_ID]
        port_no = 1
        vlan_name = 'student'
        filter_id = 'block_http'
        for handler in (self.dot1x.logoff_handler, self.dot1x.failure_handler):
            handler('0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no))
        self.dot1x.auth_handler(
            '0e:00:00:00:00:ff', faucet_dot1x.get_mac_str(valve_index, port_no),
            vlan_name=vlan_name, filter_id=filter_id)


class ValveDot1xACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dot1x ACLs."""

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

    CONFIG = f"""
{ACL_CONFIG}
dps:
    s1:
{DOT1X_ACL_CONFIG}
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
"""


class ValveDot1xMABSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dot1x MAB."""

    CONFIG = f"""
dps:
    s1:
{DOT1X_CONFIG}
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
"""


class ValveDot1xDynACLSmokeTestCase(ValveDot1xSmokeTestCase):
    """Smoke test to check dot1x can be initialized with dynamic dot1x ACLs."""
    CONFIG = f"""
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
{DOT1X_CONFIG}
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
"""

    def setUp(self):
        self.setup_valves(self.CONFIG)

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


if __name__ == "__main__":
    unittest.main()  # pytype: disable=module-attr
