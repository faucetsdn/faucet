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


class FctlTestCase(unittest.TestCase):

    FCTL = os.path.join(SRC_DIR, 'fctl.py')

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def run_fctl(self, prom_input, fctl_args, expected_output):
        """Ensure fctl succeeds and returns expected output."""
        prom_input_file_name = os.path.join(self.tmpdir, 'prom_input.txt')
        with open(prom_input_file_name, 'w') as prom_input_file:
            prom_input_file.write(prom_input)
        fctl_cli = ' '.join(
            ['python3', self.FCTL, '--endpoints=file:%s' % prom_input_file_name] + fctl_args)
        retcode, output = subprocess.getstatusoutput(fctl_cli)
        self.assertEqual(0, retcode, msg='%s returned %d' % (
            fctl_cli, retcode))
        output = output.strip()
        expected_output = expected_output.strip()
        self.assertEqual(output, expected_output)

    def test_macs(self):
        prom_input = """
learned_macs{dp_id="0xb827eb608918",n="3",port="17",vlan="2004"} 180725257428205.0
"""
        expected_output = """
learned_macs	[('dp_id', '0xb827eb608918'), ('n', '3'), ('port', '17'), ('vlan', '2004')]	a4:5e:60:c5:5c:ed
"""
        self.run_fctl(
            prom_input,
            ['--metrics=learned_macs', '--labels=dp_id:0xb827eb608918'],
            expected_output)


if __name__ == "__main__":
    unittest.main()
