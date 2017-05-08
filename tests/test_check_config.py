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
import tempfile
import unittest


SRC_DIR = '../faucet'


class CheckConfigTestCase(unittest.TestCase):

    CHECK_CONFIG = os.path.join(SRC_DIR, 'check_faucet_config.py')

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_check_config(self, config):
        conf_file = os.path.join(self.tmpdir, 'faucet.yaml')
        open(conf_file, 'w').write(config)
        return os.system('python %s %s' % (self.CHECK_CONFIG, conf_file))

    def check_config_success(self, config):
        self.assertEquals(0, self.run_check_config(config))

    def check_config_failure(self, config):
        self.assertNotEquals(0, self.run_check_config(config))

    def test_minimal(self):
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


if __name__ == "__main__":
    unittest.main()
