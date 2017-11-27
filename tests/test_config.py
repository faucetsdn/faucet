#!/usr/bin/env python3

"""Test config parsing"""

import logging
import shutil
import tempfile
import unittest
import os
from faucet import config_parser as cp

LOGNAME = '/dev/null'


class TestConfig(unittest.TestCase):
    """Test config parsing raises correct exception."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        logging.disable(logging.NOTSET)
        shutil.rmtree(self.tmpdir)

    def create_config_file(self, config):
        """Returns file path to file containing the config parameter."""
        conf_file_name = os.path.join(self.tmpdir, 'faucet.yaml')
        with open(conf_file_name, 'w') as conf_file:
            conf_file.write(config)
        return conf_file_name

    def run_function_with_config(self, config, function):
        """Return False if provided function raises InvalidConfigError."""
        conf_file = self.create_config_file(config)
        try:
            function(conf_file, LOGNAME)
        except cp.InvalidConfigError:
            return False
        return True

    def check_config_failure(self, config, function):
        """Ensure config parsing reported as failed."""
        self.assertEqual(
            self.run_function_with_config(config, function), False)

    def check_config_success(self, config, function):
        """Ensure config parsing reported succeeded."""
        self.assertEqual(
            self.run_function_with_config(config, function), True)

    def test_config_contains_only_int(self):
        """Test that config is invalid when only an int"""
        config = """5"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_float(self):
        """Test that config is invalid when only a float"""
        config = """5.5"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_str(self):
        """Test config is invalid when only a string"""
        config = """aaaa"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_boolean(self):
        """Test config is invalid when only a boolean"""
        config = """False"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_datetime(self):
        """Test that config is invalid when only a datetime object"""
        config = """1967-07-31"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_dash(self):
        """Test that config is invalid when only only a -"""
        config = """-"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_contains_only_array(self):
        """Test that config is invalid when only only [2, 2]"""
        config = """[2, 2]"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_only_empty_array(self):
        """Test that config is invalid when only only []"""
        config = """[]"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unconfigured_acl(self):
        """Test that config is invalid when there are unconfigured acls"""
        acl_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                acl_in: access-port-protect
                tagged_vlans: [office]
"""
        self.check_config_failure(acl_config, cp.dp_parser)

    def test_unconfigured_vlan_acl(self):
        """Test that config is invalid when only there are unconfigured acls"""
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
                tagged_vlans: [office]
"""
        self.check_config_failure(acl_config, cp.dp_parser)

    def test_config_routes_are_empty(self):
        """Test that config is invalid when vlan routes are empty"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: 
                ip_gw:
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_routes_not_strings(self):
        """Test config is invalid when vlan routes are not strings"""
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: 5.5
                ip_gw: []
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_vips_not_strings(self):
        """Test that config is invalid when faucet_vips does not contain strings"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: [False, 5.5, []]
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_faucet_invalid_vips(self):
        """Test that config is rejected if faucet_vips does not contain valid ip addresses"""
        config = """
vlans:
    office:
        vid: 100
        faucet_vips: ['aaaaa', '', '123421342']
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_vlans_is_empty(self):
        """Test that config is rejected when vlans is empty"""
        config = """
vlans:
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_dps_is_empty(self):
        """Test that config is rejected when dps is empty"""
        config = """
vlans:
    office:
        vid: 100
dps:
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_including_invalid_files(self):
        """Test that config is rejected when including invalid files"""
        include_config = """
include: [-, False, 1967-06-07, 5.5, [5], {'5': 5}, testing]
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            5:
                tagged_vlans: [office]
"""
        self.check_config_failure(include_config, cp.dp_parser)

    def test_config_vlans_on_stack(self):
        """Test that config is rejected vlans on a stack interface."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                native_vlan: office
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_stack(self):
        """Test valid stacking config."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        hardware: "Open vSwitch"
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        hardware: "Open vSwitch"
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_success(config, cp.dp_parser)

    def test_port_number(self):
        """Test port number is valid."""
        port_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                native_vlan: office
"""
        self.check_config_failure(port_config, cp.dp_parser)

    def test_one_port_dp(self):
        """Test port number is valid."""
        port_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            testing:
                number: 1
                native_vlan: office
"""
        self.check_config_success(port_config, cp.dp_parser)

    def test_dp_id_too_big(self):
        """Test DP ID is valid."""
        toobig_dp_id_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0xfffffffffffffffffffffffffffffffff
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(toobig_dp_id_config, cp.dp_parser)

    def test_invalid_vid(self):
        """Test VID is valid."""
        vlan_config = """
vlans:
    office:
        vid: 10000
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(vlan_config, cp.dp_parser)

    def test_routers_empty(self):
        """Test with empty router config."""
        router_config = """
routers:
    router-1:
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(router_config, cp.dp_parser)

    def test_valid_mac(self):
        """Test with valid MAC."""
        mac_config = """
vlans:
    office:
        vid: 100
        faucet_mac: '11:22:33:44:55:66'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_success(mac_config, cp.dp_parser)

    def test_invalid_mac(self):
        """Test with invalid MAC."""
        mac_config = """
vlans:
    office:
        vid: 100
        faucet_mac: '11:22:33:44:55:66:77:88'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(mac_config, cp.dp_parser)

    def test_empty_mac(self):
        """Test with empty MAC."""
        mac_config = """
vlans:
    office:
        vid: 100
        faucet_mac: ''
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(mac_config, cp.dp_parser)

    def test_empty_vid(self):
        """Test empty VID."""
        vlan_config = """
vlans:
    office:
        vid:
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(vlan_config, cp.dp_parser)

    def test_empty_interfaces(self):
        """Test empty interfaces."""
        interfaces_config = """
vlans:
    office:
        vid:
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(interfaces_config, cp.dp_parser)

    def test_invalid_interfaces(self):
        """Test invalid interfaces."""
        interfaces_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces: {'5': 5}
"""
        self.check_config_failure(interfaces_config, cp.dp_parser)

    def test_unresolved_mirror_ports(self):
        unresolved_mirror_port_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                mirror: UNRESOLVED
                allow: 1
"""
        self.check_config_failure(unresolved_mirror_port_config, cp.dp_parser)

    def test_unresolved_output_ports(self):
        unresolved_output_port_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                output:
                    port: UNRESOLVED
                allow: 1
"""
        self.check_config_failure(unresolved_output_port_config, cp.dp_parser)

    def test_unknown_output_ports(self):
        unknown_output_port_config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
                acl_in: mirror_all
acls:
    mirror_all:
        - rule:
            actions:
                output:
                    port: 2
                allow: 1
"""
        self.check_config_failure(unknown_output_port_config, cp.dp_parser)



if __name__ == "__main__":
    unittest.main()
