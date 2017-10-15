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
        name: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
"""
        self.check_config_success(minimal_conf)

    def test_tabs(self):
        """Test that config with tabs is rejected."""
        tab_conf = """
vlans:
    100:
        	name: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
"""
        self.check_config_failure(tab_conf)

    def test_unknown_dp_config_item(self):
        """Test that an unknown DP field is rejected."""
        unknown_dp_config_item = """
vlans:
    100:
        name: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
        broken: something
"""
        self.check_config_failure(unknown_dp_config_item)

    def test_toplevel_unknown_config(self):
        """Test that an unknown toplevel config section is rejected."""
        toplevel_unknown_config = """
vlans:
    100:
        name: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
unknown_thing: 1
"""
        self.check_config_failure(toplevel_unknown_config)

    def test_toplevel_unknown_hardware(self):
        """Test that unknown hardware is rejected."""
        unknown_hardware_config = """
vlans:
    100:
        name: "100"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'NOTSUPPORTED'
"""
        self.check_config_failure(unknown_hardware_config)

    def test_unknown_router_vlan(self):
        """Test that a unknown router VLAN is rejected."""
        unknown_router_vlan_config = """
routers:
    router-1:
        vlans: [100, 101]
vlans:
    100:
        name: "100"
    200:
        name: "200"
dps:
    switch1:
        dp_id: 0xcafef00d
        hardware: 'Open vSwitch'
"""
        self.check_config_failure(unknown_router_vlan_config)


if __name__ == "__main__":
    unittest.main()
