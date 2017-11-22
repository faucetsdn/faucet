""" """
#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import os
from faucet import config_parser as cp

SRC_DIR = '../faucet'
LOGNAME = 'test_config'

class TestConfig(unittest.TestCase): 

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def create_config_file(self, config):
        """Returns the file path to the created file containing the config parameter"""
        conf_file_name = os.path.join(self.tmpdir, 'faucet.yaml')
        with open(conf_file_name, 'w') as conf_file:
            conf_file.write(config)
        return conf_file_name

    def run_function_with_config(self, config, function):
        conf_file = self.create_config_file(config)
        try:
           function(conf_file, LOGNAME)
        except cp.InvalidConfigError:
           return False
        return True

    def check_config_failure(self, config, function):
        self.assertEqual(self.run_function_with_config(config, function), False)


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

    def test_config_contains_only_boolean(self):
        """Test config is invalid when only a boolean"""
        config = """False"""
        self.check_config_failure(config, cp.dp_parser)

    def test_config_conains_only_datetime_object(self):
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

    def test_config_contains_only_empty_array(self):
        """Test that config is invalid when only only []"""
        config = """[]"""
        self.check_config_failure(config, cp.dp_parser)

    def test_referencing_unconfigured_acl(self):
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
        self.check_config_failure(acl_config, cp._config_parser_v2)

    def test_referencing_unconfigured_vlan_acl(self):
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
        self.check_config_failure(acl_config, cp._config_parser_v2)

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
        self.check_config_failure(config, cp._config_parser_v2)

    def test_config_routes_are_not_strings(self):
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
        self.check_config_failure(config, cp._config_parser_v2)

    def test_config_vlan_vips_are_not_strings(self):
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
        self.check_config_failure(config, cp._config_parser_v2)


if __name__ == "__main__":
    unittest.main()
