#!/usr/bin/env python

"""Test fctl FAUCET CLI utility."""

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

import os
import copy
import shutil
import subprocess
import tempfile
import unittest

from faucet import fctl

class FctlTestCaseBase(unittest.TestCase): # pytype: disable=module-attr
    """Base class for fctl tests."""

    DEFAULT_VALUES = {
        'dp_id': '0xb827eb608918',
        'mac_addr': 'a4:5e:60:c5:5c:ed',
        'metrics': 'learned_macs',
        'n': 3,
        'port': '17',
        'vlan': '2004',
        'value': 180725257428205.0
    }

    SRC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../faucet')

    FCTL_BASE_ARGS = [
        '--metrics={metrics}'.format(**DEFAULT_VALUES),
        '--labels=dp_id:{dp_id}'.format(**DEFAULT_VALUES)
        ]
    FCTL = os.path.join(SRC_DIR, 'fctl.py')
    tmpdir = None
    prom_input_file_name = None

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.prom_input_file_name = os.path.join(self.tmpdir, 'prom_input.txt')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def fctl_args(self, extra_args=None):
        """generate argument list for fctl"""
        result = copy.copy(self.FCTL_BASE_ARGS)
        result += ['--endpoints=file:%s' % self.prom_input_file_name]
        if extra_args is not None:
            result += extra_args
        return result

    def learned_macs_prom(self, overwrite_labels=None):
        """generate prometheus formated data"""
        labels = copy.copy(self.DEFAULT_VALUES)
        if overwrite_labels is not None:
            labels.update(overwrite_labels)
        result = """
{metrics}{{dp_id="{dp_id}",n="{n}",port="{port}",vlan="{vlan}"}}\t{value}"""
        return result.format(**labels).strip()

    def learned_macs_result(self, overwrite_labels=None):
        """generate expected output data"""
        labels = copy.copy(self.DEFAULT_VALUES)
        if overwrite_labels is not None:
            labels.update(overwrite_labels)
        result = """
{metrics}\t[('dp_id', '{dp_id}'), ('n', '{n}'), ('port', '{port}'), ('vlan', '{vlan}')]\t{mac_addr}
"""
        return result.format(**labels).strip()

class FctlTestCase(FctlTestCaseBase):
    """Drive fctl from shell."""

    def run_fctl(self, prom_input, expected_output, extra_args=None):
        """Ensure fctl succeeds and returns expected output."""
        with open(self.prom_input_file_name, 'w') as prom_input_file:
            prom_input_file.write(prom_input)
        fctl_cli = ' '.join(
            ['python3', self.FCTL]  + self.fctl_args(extra_args))
        retcode, output = subprocess.getstatusoutput(fctl_cli) # pytype: disable=module-attr
        self.assertEqual(0, retcode, msg='%s returned %d' % (
            fctl_cli, retcode))
        output = output.strip()
        self.assertEqual(output, expected_output)

    def test_macs(self):
        self.run_fctl(self.learned_macs_prom(), self.learned_macs_result())

    def test_display_labels(self):
        expected_output = """
learned_macs\t[('dp_id', '{dp_id}')]\t{mac_addr}
""".format(**self.DEFAULT_VALUES).strip()

        self.run_fctl(
            self.learned_macs_prom(),
            expected_output,
            extra_args=['--display-labels=dp_id'])


class FctlClassTestCase(FctlTestCaseBase):
    """Test fctl internal methods."""

    def test_http_fail(self):
        with open(os.devnull, 'w') as err_output_file:
            self.assertEqual(
                None,
                fctl.scrape_prometheus(
                    ['http://127.0.0.1:23'], err_output_file=err_output_file))

    def test_macs(self):
        prom_input_file_name = os.path.join(self.tmpdir, 'prom_input.txt')
        with open(prom_input_file_name, 'w') as prom_input_file:
            prom_input_file.write(self.learned_macs_prom())
        (
            endpoints,
            report_metrics,
            label_matches,
            nonzero_only,
            _
            ) = fctl.parse_args(self.fctl_args())
        metrics = fctl.scrape_prometheus(endpoints)
        report_out = fctl.report_label_match_metrics( # pylint: disable=assignment-from-no-return
            report_metrics=report_metrics,
            metrics=metrics,
            label_matches=label_matches,
            nonzero_only=nonzero_only)
        self.assertEqual(report_out, self.learned_macs_result())


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
