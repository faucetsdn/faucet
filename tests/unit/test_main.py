#!/usr/bin/env python

"""Test FAUCET main."""

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

import unittest

# pylint: disable=no-name-in-module
# pylint: disable=import-error
from faucet.__main__ import parse_args, build_ryu_args


class MainTestCase(unittest.TestCase): # pytype: disable=module-attr
    """Test __main__ methods."""

    def test_parse_args(self):
        """Sanity check argument parsing."""
        self.assertFalse(parse_args([]).verbose)
        self.assertTrue(parse_args(['--verbose']).verbose)

    def test_build_ryu_args(self):
        """Test build_ryu_args()."""
        self.assertTrue(build_ryu_args(['faucet', '--use-stderr', '--use-syslog', '--verbose']))
        self.assertTrue(build_ryu_args(['gauge', '--use-stderr', '--use-syslog', '--verbose']))
        self.assertFalse(build_ryu_args(['faucet', '--version']))


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
