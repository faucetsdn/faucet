#!/usr/bin/env python

# Copyright (C) 2015 Brad Cowie, Christopher Lorier and Joe Stringer.
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
import shutil
import subprocess
import tempfile
import unittest


SRC_DIR = '../faucet'


class CheckConfigTestCase(unittest.TestCase):

    CHECK_CONFIG = 'check_faucet_config.py'

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        shutil.copy(os.path.join(SRC_DIR, self.CHECK_CONFIG), self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_check_config(self, config, expected_ok):
        conf_file_name = os.path.join(self.tmpdir, 'faucet.yaml')
        with open(conf_file_name, 'w') as conf_file:
            conf_file.write(config)
        check_cli = ['python3', os.path.join(self.tmpdir, self.CHECK_CONFIG), conf_file_name]
        result_ok = False
        try:
            subprocess.check_output(
                check_cli, stderr=subprocess.STDOUT)
            result_ok = True
        except subprocess.CalledProcessError as err:
            if expected_ok:
                print(('%s returned %d (%s)' % (
                    ' '.join(check_cli), err.returncode, err.output)))
        return expected_ok == result_ok

    def check_config_success(self, config):
        self.assertTrue(self.run_check_config(config, True))

    def check_config_failure(self, config):
        self.assertTrue(self.run_check_config(config, False))

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

    def test_bad_acl_port(self):
        """Test that an ACL with a bad match field is rejected."""
        acl_config = """
vlans:
    100:
        description: "100"
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
    switch2:
        dp_id: 0xdeadbeef
        hardware: 'Open vSwitch'
        interfaces:
            1:
                native_vlan: 200
"""
        self.check_config_success(vlan_config)

    def test_referencing_unconfigured_acl(self):
        """Test that config is rejected when referencing unconfigured acl"""
        acl_config = """
vlans:
    guest:
        vid: 200
dps:
    sw2:
        dp_id: 0x2
        hardware: "Allied-Telesis"
        interfaces:
            1:
                name: "pi"
                description: "Raspberry Pi"
                native_vlan: guest
                acl_in: access-port-protect
"""
        self.check_config_failure(acl_config)

    def test_referencing_unconfigured_vlan_acl(self):
        """Test that config is rejected when referencing an unconfigured acl"""
        acl_config = """
vlans:
    office:
        vid: 100
        acl_in: office-vlan-protect
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: access-port-protect
"""
        self.check_config_failure(acl_config)

    def test_config_contains_only_int(self):
        """Test that config is rejected when config is only an int"""
        config = """5"""
        self.check_config_failure(config)

    def test_config_contains_only_float(self):
        """Test that config is rejected when config is only a float"""
        config = """5.5"""
        self.check_config_failure(config)

    def test_config_contains_only_str(self):
        """Test that config is rejected when config is only a string"""
        config = """aaaa"""
        self.check_config_failure(config)

    def test_config_contains_only_boolean(self):
        """Test that config is rejected when config is only a boolean"""
        config = """False"""
        self.check_config_failure(config)

    def test_config_conains_only_datetime_object(self):
        """Test that config is rejected when config is only a datetime object"""
        config = """1967-07-31"""
        self.check_config_failure(config)

    def test_config_contains_only_dash(self):
        """Test that config is rejected when config is only a -"""
        config = """-"""
        self.check_config_failure(config)

    def test_config_contains_only_array(self):
        """Test that config is rejected when config is only [2, 2]"""
        config = """[2, 2]"""
        self.check_config_failure(config)

    def test_config_contains_only_empty_array(self):
        """Test that config is rejected when config is only []"""
        config = """[]"""
        self.check_config_failure(config)

    def test_config_routes_are_empty(self):
        """Test that config is rejected when vlan routes are empty"""
        config = """
vlans:
    office:
        routes:
            - route:
                ip_dst: 
                ip_gw: 
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config)

    def test_config_routes_are_not_strings(self):
        """Test that config is rejected when vlan routes are not strings"""
        config = """
vlans:
    office:
        routes:
            - route:
                ip_dst: []
                ip_gw: 5.5
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config)

    def test_config_vlan_vips_are_not_strings(self):
        """Test that config is rejected when faucet_vips does not contain any strings"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: [False, 5.5, 4584594]
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config)

    def test_config_vlan_route_contains_invalid_ip_addresses(self):
        """Test that config is rejected when vlan routes does not contain valid ip addresses"""
        config = """
vlans:
    office:
        routes:
            - route:
                ip_dst: '0x985'
                ip_gw: '0x12ca'
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config)

    def test_config_faucet_vips_contains_invalid_ip_addresses(self):
        """Test that config is rejected if faucet_vips does not contain valid ip addresses"""
        config = """
vlans:
    office:
        faucet_vips: ['aaaaa', '', '123421342']
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config)

    def test_routes_with_invalid_ip_addresses(self):
        """Test that config is rejected if routes do not contain valid ip addresses"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: 'aaaaa'
                ip_gw: '111111'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config)
    
    def test_config_does_not_form_a_dict(self):
        """Test that config is rejected when it does not form a dictionary"""
        config = """
vlans: 
"""
        self.check_config_failure(config)

if __name__ == "__main__":
    unittest.main()
