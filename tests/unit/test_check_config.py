#!/usr/bin/env python

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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

import logging
import os
import shutil
import tempfile
import unittest
import re

from faucet.check_faucet_config import check_config


class CheckConfigTestCase(unittest.TestCase): # pytype: disable=module-attr
    """Test that check config script handles various broken configs."""

    tmpdir = None

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_check_config(self, config, expected_ok):
        conf_file_name = os.path.join(self.tmpdir, 'faucet.yaml')
        with open(conf_file_name, 'w') as conf_file:
            conf_file.write(config)
        with open(os.devnull, 'w') as check_output_file:
            result_ok = check_config( # pylint: disable=unexpected-keyword-arg
                [conf_file_name], logging.FATAL, check_output_file)
        return expected_ok == result_ok

    def _deprecated_acl_check(self, config, success):
        # TODO: Check acls_in work now acl_in is deprecated, remove in future
        if 'acl_in' in config and not 'acls_in' in config:
            acls_cfg = re.sub('(acl_in: )(.*)', 'acls_in: [\\2]', config)
            self.assertTrue(self.run_check_config(acls_cfg, success))

    def check_config_success(self, config):
        self.assertTrue(self.run_check_config(config, True))
        self._deprecated_acl_check(config, True)

    def check_config_failure(self, config):
        self.assertTrue(self.run_check_config(config, False))
        self._deprecated_acl_check(config, False)

    def test_no_dps(self):
        no_dps_conf = """
vlans:
    100:
        description: "100"
"""
        self.check_config_failure(no_dps_conf)

    def test_minimal(self):
        """Test minimal correct config."""
        minimal_conf = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_success(minimal_conf)

    def test_include_optional(self):
        """Test minimal include optional correct config."""
        minimal_conf = """
include-optional: ['/nonexistant']
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_success(minimal_conf)

    def test_include_required(self):
        """Test minimal include optional correct config."""
        minimal_conf = """
include: ['/nonexistant']
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(minimal_conf)

    def test_invalid_vid(self):
        """Test invalid VID."""
        invalid_vid_conf = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 4097
"""
        self.check_config_failure(invalid_vid_conf)

    def test_vlan_name(self):
        """Test vlan referred by its name."""
        vlan_name_conf = """
vlans:
    finance:
        description: "FINANCE VLAN"
        vid: 100
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: finance
"""
        self.check_config_success(vlan_name_conf)

    def test_no_interfaces(self):
        """Test DP has no interfaces."""
        no_interfaces_conf = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
"""
        self.check_config_failure(no_interfaces_conf)

    def test_tabs(self):
        """Test that config with tabs is rejected."""
        tab_conf = """
vlans:
    100:
        	description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(tab_conf)

    def test_no_vlan(self):
        """Test port without a VLAN rejected."""
        no_vlan_config = """
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'NOTSUPPORTED'
        interfaces:
            1:
                description: 'vlanless'
"""
        self.check_config_failure(no_vlan_config)

    def test_unknown_dp_config_item(self):
        """Test that an unknown DP field is rejected."""
        unknown_dp_config_item = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        broken: something
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(unknown_dp_config_item)

    def test_toplevel_unknown_config(self):
        """Test that an unknown toplevel config section is rejected."""
        toplevel_unknown_config = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
unknown_thing: 1
"""
        self.check_config_failure(toplevel_unknown_config)

    def test_toplevel_unknown_hardware(self):
        """Test that unknown hardware is rejected."""
        unknown_hardware_config = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'NOTSUPPORTED'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(unknown_hardware_config)

    def test_routing_stacking(self):
        """Test that routing and stacking cannot be enabled together."""
        routing_stacking_config = """
vlans:
    100:
        description: "100"
        faucet_vips: ['1.2.3.4/24']
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(routing_stacking_config)

    def test_stacking_noroot(self):
        """Test that a stacking root is defined."""
        stacking_config = """
vlans:
    100:
        description: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        stack:
            priority: 0
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(stacking_config)

    def test_bad_acl_action(self):
        """Test that an ACL with a bad match field is rejected."""
        acl_config = """
vlans:
    100:
        description: "100"
acls:
    101:
        - rule:
            nogood: '0e:00:00:00:02:02'
            actions:
                output:
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_failure(acl_config)

    def test_bad_acl_vlan(self):
        """Test that an ACL with a bad match field is rejected."""
        acl_config = """
vlans:
    100:
        description: "100"
        acl_in: 101
acls:
    101:
        - rule:
            nogood: "0e:00:00:00:02:02"
            actions:
                output:
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
"""
        self.check_config_failure(acl_config)

    def test_good_acl(self):
        """Test that an ACL with good match field is accepted."""
        acl_config = """
vlans:
    100:
        description: "100"
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
                output:
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_success(acl_config)

    def test_ports_good_acl(self):
        """Test that an ACL with good match field is accepted."""
        acl_config = """
vlans:
    100:
        description: "100"
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
                output:
                    ports: [1, 2]
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
            2:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_success(acl_config)

    def test_router_resolved_vlans(self):
        """Test that VLANs get resolved by routers."""
        vlan_config = """
vlans:
    100:
        description: "100"
    200:
        description: "200"
routers:
    router1:
        vlans: [100, 200]
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 100
            2:
                native_vlan: 200
    switch2:
        dp_id: 0xdeadbeef
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 200
"""
        self.check_config_success(vlan_config)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
