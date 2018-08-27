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

from deb_pkg_tools.control import deb822_from_string, parse_control_fields
from deb_pkg_tools.deps import VersionedRelationship

try:
    from pip._internal.req import parse_requirements, InstallRequirement # for pip >= 10
except ImportError:
    from pip.req import parse_requirements, InstallRequirement # for pip <= 9.0.3


class CheckDebianPackageTestCase(unittest.TestCase): # pytype: disable=module-attr
    """Test debian packaging."""

    def setUp(self):
        SRC_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../../')
        self.control_file = os.path.join(SRC_DIR, 'debian/control')
        self.requirements_file = os.path.join(SRC_DIR, 'requirements.txt')

        self.dpkg_name = {
            'msgpack-python': 'python3-msgpack',
            'pyyaml': 'python3-yaml'
            }

        with open(self.control_file) as handle:
            control = handle.read()

        faucet_dpkg = str()
        for line in control.split("\n"):
            if line.startswith("Package: python3-faucet"):
                faucet_dpkg += line
            elif faucet_dpkg:
                if not line:
                    break
                faucet_dpkg += "{}\n".format(line)

        faucet_dpkg = parse_control_fields(deb822_from_string(faucet_dpkg))
        self.faucet_dpkg_deps = {}
        for dep in faucet_dpkg['Depends']:
            if isinstance(dep, VersionedRelationship):
                if dep.name not in self.faucet_dpkg_deps:
                    self.faucet_dpkg_deps[dep.name] = []
                self.faucet_dpkg_deps[dep.name].append("{}{}".format(dep.operator, dep.version))

    def test_every_pip_requirement_in_debian_package(self):
        """Test pip requirements are listed as dependencies on debian package."""

        for pip_req in parse_requirements(self.requirements_file,
                                                  session="unittest"):
            if isinstance(pip_req, InstallRequirement):
                if pip_req.name in self.dpkg_name:
                    dpkg_name = self.dpkg_name[pip_req.name]
                else:
                    dpkg_name = "python3-{}".format(pip_req.name)

                self.assertIn(dpkg_name, self.faucet_dpkg_deps)

    def test_every_pip_requirement_has_matching_version_in_debian_package(self):
        """Test pip requirements versions match debian package dependencies."""

        for pip_req in parse_requirements(self.requirements_file,
                                                  session="unittest"):
            if isinstance(pip_req, InstallRequirement):
                if pip_req.name in self.dpkg_name:
                    dpkg_name = self.dpkg_name[pip_req.name]
                else:
                    dpkg_name = "python3-{}".format(pip_req.name)

                if pip_req.req.specifier:
                    pip_req_version = str(pip_req.req.specifier)
                    debian_package_dependencies = [
                        pip_req.name+x for x in self.faucet_dpkg_deps[dpkg_name]
                    ]
                    if str(pip_req_version).startswith('=='):
                        # debian/control is annoying about how it handles exact
                        # versions, calculate the debian equivalent of the
                        # pip requirements match and compare that
                        lower_match = pip_req_version.replace('==', '>=')
                        upper_match = pip_req_version.replace('==', '<<').split('.')
                        upper_match[-1] = str(int(upper_match[-1]) + 1)
                        upper_match = '.'.join(upper_match)

                        self.assertIn(pip_req.name+lower_match, debian_package_dependencies)
                        self.assertIn(pip_req.name+upper_match, debian_package_dependencies)
                    else:
                        self.assertIn(pip_req.name+pip_req_version, debian_package_dependencies)


if __name__ == "__main__":
    unittest.main() # pytype: disable=module-attr
