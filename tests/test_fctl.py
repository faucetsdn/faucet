#!/usr/bin/env python

"""Test fctl FAUCET CLI utility."""

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

from faucet import fctl

DP_ID = '0xb827eb608918'
SRC_DIR = '../faucet'

METRICS = 'learned_macs'
LEARNED_MACS_PROM = ("""
%s{dp_id="%s",n="3",port="17",vlan="2004"} 180725257428205.0
""" % (METRICS, DP_ID)).strip()
LEARNED_MACS_OUT = ("""
%s\t[('dp_id', '%s'), ('n', '3'), ('port', '17'), ('vlan', '2004')]\ta4:5e:60:c5:5c:ed
""" % (METRICS, DP_ID)).strip()
FCTL_BASE_ARGS = ['--metrics=%s' % METRICS, '--labels=dp_id:%s' % DP_ID]


class FctlTestCaseBase(unittest.TestCase):
    """Base class for fctl tests."""

    FCTL = os.path.join(SRC_DIR, 'fctl.py')
    tmpdir = None

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def fctl_args(self, prom_input_file_name):
        return FCTL_BASE_ARGS + ['--endpoints=file:%s' % prom_input_file_name]


class FctlTestCase(FctlTestCaseBase):
    """Drive fctl from shell."""

    def run_fctl(self, prom_input, expected_output):
        """Ensure fctl succeeds and returns expected output."""
        prom_input_file_name = os.path.join(self.tmpdir, 'prom_input.txt')
        with open(prom_input_file_name, 'w') as prom_input_file:
            prom_input_file.write(prom_input)
        fctl_cli = ' '.join(
            ['python3', self.FCTL]  + self.fctl_args(prom_input_file_name))
        retcode, output = subprocess.getstatusoutput(fctl_cli)
        self.assertEqual(0, retcode, msg='%s returned %d' % (
            fctl_cli, retcode))
        output = output.strip()
        self.assertEqual(output, expected_output)

    def test_macs(self):
        self.run_fctl(LEARNED_MACS_PROM, LEARNED_MACS_OUT)


class FctlClassTestCase(FctlTestCaseBase):
    """Test fctl internal methods."""

    def test_macs(self):
        prom_input_file_name = os.path.join(self.tmpdir, 'prom_input.txt')
        with open(prom_input_file_name, 'w') as prom_input_file:
            prom_input_file.write(LEARNED_MACS_PROM)
        fctl_args = self.fctl_args(prom_input_file_name)
        (endpoints, report_metrics, label_matches, nonzero_only) = fctl.parse_args(fctl_args)
        metrics = fctl.scrape_prometheus(endpoints)
        report_out = fctl.report_label_match_metrics( # pylint: disable=assignment-from-no-return
            report_metrics=report_metrics,
            metrics=metrics,
            label_matches=label_matches,
            nonzero_only=nonzero_only)
        self.assertEqual(report_out, LEARNED_MACS_OUT)


if __name__ == "__main__":
    unittest.main()
