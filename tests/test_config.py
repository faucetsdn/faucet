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

    def conf_file_name(self):
        return os.path.join(self.tmpdir, 'faucet.yaml')

    def create_config_file(self, config):
        """Returns file path to file containing the config parameter."""
        conf_file_name = self.conf_file_name()
        with open(conf_file_name, 'wb') as conf_file:
            if isinstance(config, bytes):
                conf_file.write(config)
            else:
                conf_file.write(config.encode('utf-8'))
        return conf_file_name

    def run_function_with_config(self, config, function, before_function=None):
        """Return False if provided function raises InvalidConfigError."""
        conf_file = self.create_config_file(config)
        if before_function:
            before_function()
        try:
            function(conf_file, LOGNAME)
        except cp.InvalidConfigError:
            return False
        return True

    def check_config_failure(self, config, function, before_function=None):
        """Ensure config parsing reported as failed."""
        self.assertEqual(
            self.run_function_with_config(config, function, before_function), False)

    def check_config_success(self, config, function, before_function=None):
        """Ensure config parsing reported succeeded."""
        self.assertEqual(
            self.run_function_with_config(config, function, before_function), True)

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
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_unconfigured_vlan_acl(self):
        """Test that config is invalid when only there are unconfigured acls"""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

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
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

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
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_one_port_dp(self):
        """Test port number is valid."""
        config = """
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
        self.check_config_success(config, cp.dp_parser)

    def test_dp_id_too_big(self):
        """Test DP ID is valid."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_vid(self):
        """Test VID is valid."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_routers_empty(self):
        """Test with empty router config."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_valid_mac(self):
        """Test with valid MAC."""
        config = """
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
        self.check_config_success(config, cp.dp_parser)

    def test_invalid_mac(self):
        """Test with invalid MAC."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_mac(self):
        """Test with empty MAC."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_vid(self):
        """Test empty VID."""
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_interfaces(self):
        """Test empty interfaces."""
        config = """
vlans:
    office:
        vid:
dps:
    sw1:
        dp_id: 0x1
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_interfaces(self):
        """Test invalid interfaces."""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces: {'5': 5}
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_unresolved_mirror_ports(self):
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_unresolved_output_ports(self):
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_unknown_output_ports(self):
        config = """
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
        self.check_config_failure(config, cp.dp_parser)

    def test_port_range_valid_config(self):
        """Test if port range config applied correctly"""
        config = """
vlans:
    office:
        vid: 100
    guest:
        vid: 200
dps:
    sw1:
        dp_id: 0x1
        interface_ranges:
            1-4,6,port8:
                native_vlan: office
                max_hosts: 2
                permanent_learn: True
            port10-11:
                native_vlan: guest
                max_hosts: 2
        interfaces:
            1:
                max_hosts: 4
                description: "video conf"
"""
        conf_file = self.create_config_file(config)
        _, dps = cp.dp_parser(conf_file, LOGNAME)
        dp = dps[0]
        self.assertEqual(len(dp.ports), 8)
        self.assertTrue(all([p.permanent_learn for p in dp.ports.values() if p.number < 9]))
        self.assertTrue(all([p.max_hosts == 2 for p in dp.ports.values() if p.number > 1]))
        self.assertTrue(dp.ports[1].max_hosts == 4)
        self.assertEqual(dp.ports[1].description, "video conf")

    def test_port_range_invalid_config(self):
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interface_ranges:
            abc:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_no_actions(self):
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            actions:
          0     allow: 0
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_ipv4(self):
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: q0.0.200.0/24
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
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_ipv6(self):
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv6_src: zyx
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
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_mask(self):
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 10/0.200.0/24
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
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_udp_port(self):
        config = """
acls:
    access-port-protect:
        - rule:
            udp_src: v7
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
        self.check_config_failure(config, cp.dp_parser)

    def test_acl_invalid_rule_name(self):
        config = """
acls:
    access-port-protect:
        - xrule:
            udp_src: v7
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
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_char(self):
        config = b'\x63\xe1'
        self.check_config_failure(config, cp.dp_parser)

    def test_perm_denied(self):

        def unreadable():
            """Make config unreadable."""
            os.chmod(self.conf_file_name(), 0)

        config = ''
        self.check_config_failure(config, cp.dp_parser, before_function=unreadable)

    def test_missing_route_config(self):
        config = """
vlans:
    office:
        vid: 100
        routes:
            - route:
                ip_dst: '192.168.0.0/24'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""

        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_dp_conf(self):
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                description: "host1 container"
    0           native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_duplicate_keys_conf(self):
        """Test duplicate top level keys."""
        config = """
vlans:
    office:
        vid: 100
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
        self.check_config_failure(config, cp.dp_parser)

    def test_dp_id_not_a_string(self):
        """Test dp_id is not a string"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: &x1
        interfaces:
            1:
                native_vlan: office        
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_key(self):
        """Test invalid key"""
        config = """
acls:
 ?  office-vlan-protect:
        - rule:
            actions:
                allow: 1
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_acl_formation(self):
        config = """
acls:
#   office-vlan-protect:
        - rule:
            actions:
                allow: 1
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_route_value(self):
        """Test routes value forming a dictionary"""
        config = """
vlans:
    office:
        vid: 100
        routes:
        -   - route:
                ip_dst: '192.168.0.0/24'
                ip_gw: '10.0.100.2'
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_mirror_port(self):
        """Test referencing invalid mirror port"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        interfaces:
            1:
                mirror: 1"
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_invalid_include_values(self):
        """Test include directive contains invalid values"""
        config = """
include:
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
        self.check_config_failure(config, cp.dp_parser)

    def test_ipv4_src_is_empty(self):
        """Test acl ipv4_src is empty"""
        config = """ 
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv4_src: 
            actions:
                allow: 0
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_eth_dst(self):
        """Test eth_dst/dl_dst is empty"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst:
            actions:
                output:
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101     
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_router_vlan_invalid_type(self):
        """Test when router vlans forms a dict"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
               mirror: 
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_mirror_port_invalid_type(self):
        """Test when mirror port forms a dict"""
        config = """
vlans:
    100:
acls:
    101:
        - rule:
            dl_dst: "0e:00:00:00:02:02"
            actions:
               mirror: 
                    port: 1
dps:
    switch1:
        dp_id: 0xcafef00d
        interfaces:
            1:
                native_vlan: 100
                acl_in: 101
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_referencing_unconfigured_dp_in_stack(self):
        """Test when referencing a nonexistent dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    3w1:
        dp_id: 0x1
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
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_referencing_unconfigured_port_in_stack(self):
        """Test when referencing a nonexistent port for dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            9:
                stack:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_not_referencing_a_port_in_the_stack(self):
        """Test when not referencing a port in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    dp: sw2
                    0ort: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_not_referencing_a_dp_in_the_stack(self):
        """Test when not referencing a dp in a stack"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
                stack:
                    $p: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_no_rules_in_acl(self):
        """Test when no rules are present in acl"""
        config = """
acls:
    mirror_destination: {}
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_empty_ipv6_src(self):
        """Test when ipv6_src is empty"""
        config = """
acls:
    office-vlan-protect:
        - rule:
            dl_type: 0x800
            ipv6_src: 
            actions:
                allow: 0
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
"""
        self.check_config_failure(config, cp.dp_parser)

    def test_port_number_is_wrong_type(self):
        """Test when port number is a dict"""
        config = """
vlans:
    office:
        vid: 100
dps:
    sw1:
        dp_id: 0x1
        stack:
            priority: 1
        interfaces:
            1:
               number:
                    dp: sw2
                    port: 1
            2:
                native_vlan: office
    sw2:
        dp_id: 0x2
        interfaces:
            1:
                stack:
                    dp: sw1
                    port: 1
            2:
                native_vlan: office
"""
        self.check_config_failure(config, cp.dp_parser)


if __name__ == "__main__":
    unittest.main()
