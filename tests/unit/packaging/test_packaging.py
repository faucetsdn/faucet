#!/usr/bin/env python

"""Test FAUCET packaging"""

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
import unittest
import pip.req

from deb_pkg_tools.control import deb822_from_string, parse_control_fields

class CheckRequirementsTestCase(unittest.TestCase): # pytype: disable=module-attr
    """Test packaging requirements."""

    def test_requirements_match(self):
        """Test all requirements are listed as apt package dependencies."""

        SRC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../')
        control_file = os.path.join(SRC_DIR, 'debian/control')
        requirements_file = os.path.join(SRC_DIR, 'requirements.txt')

        real_name = {
            'msgpack-python': 'python3-msgpack',
            'pyyaml': 'python3-yaml'
            }

        with open(control_file) as handle:
            control = handle.read()

        faucet_dpkg = str()
        for line in control.split("\n"):
            if line.startswith("Package: python3-faucet"):
                faucet_dpkg += line
            elif len(faucet_dpkg) > 0:
                if not line:
                    break
                faucet_dpkg += "{}\n".format(line)

        faucet_dpkg = parse_control_fields(deb822_from_string(faucet_dpkg))
        faucet_dpkg_deps = [x.name for x in faucet_dpkg['Depends']]

        for item in pip.req.parse_requirements(requirements_file,
                                               session="unittest"):
            if isinstance(item, pip.req.InstallRequirement):
                if item.name in real_name:
                    self.assertIn(real_name[item.name], faucet_dpkg_deps)
                else:
                    self.assertIn("python3-{}".format(item.name), faucet_dpkg_deps)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
